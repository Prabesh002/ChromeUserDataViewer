
CC = gcc
CFLAGS = -g -I./include
LDFLAGS = -L./lib -lsqlite3 -lcrypt32 -lbcrypt  

# Directories
SRCDIR = src
OBJDIR = build
BINDIR = bin


TARGET = $(BINDIR)/MainProgram.exe

SRCS = $(SRCDIR)/test.c $(SRCDIR)/sqlite3.c
OBJS = $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

$(shell if not exist "$(OBJDIR)" mkdir "$(OBJDIR)")
$(shell if not exist "$(BINDIR)" mkdir "$(BINDIR)")

all: $(TARGET)

$(TARGET): $(OBJS) FORCE
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

FORCE:


clean:
	@echo Cleaning up...
	@if exist "$(OBJDIR)" rmdir /s /q "$(OBJDIR)"
	@if exist "$(BINDIR)" rmdir /s /q "$(BINDIR)"

rebuild: clean all

.PHONY: all clean rebuild FORCE
