/*
 * Cobalt Strike 4.X BOF compatibility layer
 * -----------------------------------------
 * The whole point of these files are to allow beacon object files built for CS
 * to run fine inside of other tools without recompiling.
 *
 * Built off of the beacon.h file provided to build for CS.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>

#include "beacon_compatibility.h"

#define DEFAULTPROCESSNAME "rundll32.exe"
#ifdef _WIN64
#define X86PATH "SysWOW64"
#define X64PATH "System32"
#else
#define X86PATH "System32"
#define X64PATH "sysnative"
#endif

#define BEACON_TOKEN_STACK_MAX 32
#define BEACON_DATA_STORE_MAX_ENTRIES 64

 /* Data Parsing. Keep the order in sync with the extern declaration in
  * beacon_compatibility.h; __C_specific_handler MUST be the last entry. */
unsigned char* InternalFunctions[BEACON_INTERNAL_FUNCTIONS_COUNT][2] = {
    {(unsigned char*)"BeaconDataParse", (unsigned char*)BeaconDataParse},
    {(unsigned char*)"BeaconDataPtr", (unsigned char*)BeaconDataPtr},
    {(unsigned char*)"BeaconDataInt", (unsigned char*)BeaconDataInt},
    {(unsigned char*)"BeaconDataShort", (unsigned char*)BeaconDataShort},
    {(unsigned char*)"BeaconDataLength", (unsigned char*)BeaconDataLength},
    {(unsigned char*)"BeaconDataExtract", (unsigned char*)BeaconDataExtract},
    {(unsigned char*)"BeaconFormatAlloc", (unsigned char*)BeaconFormatAlloc},
    {(unsigned char*)"BeaconFormatReset", (unsigned char*)BeaconFormatReset},
    {(unsigned char*)"BeaconFormatFree", (unsigned char*)BeaconFormatFree},
    {(unsigned char*)"BeaconFormatAppend", (unsigned char*)BeaconFormatAppend},
    {(unsigned char*)"BeaconFormatPrintf", (unsigned char*)BeaconFormatPrintf},
    {(unsigned char*)"BeaconFormatToString", (unsigned char*)BeaconFormatToString},
    {(unsigned char*)"BeaconFormatInt", (unsigned char*)BeaconFormatInt},
    {(unsigned char*)"BeaconPrintf", (unsigned char*)BeaconPrintf},
    {(unsigned char*)"BeaconOutput", (unsigned char*)BeaconOutput},
    {(unsigned char*)"BeaconDownload", (unsigned char*)BeaconDownload},
    {(unsigned char*)"BeaconUseToken", (unsigned char*)BeaconUseToken},
    {(unsigned char*)"BeaconRevertToken", (unsigned char*)BeaconRevertToken},
    {(unsigned char*)"BeaconIsAdmin", (unsigned char*)BeaconIsAdmin},
    {(unsigned char*)"BeaconGetSpawnTo", (unsigned char*)BeaconGetSpawnTo},
    {(unsigned char*)"BeaconSpawnTemporaryProcess", (unsigned char*)BeaconSpawnTemporaryProcess},
    {(unsigned char*)"BeaconInjectProcess", (unsigned char*)BeaconInjectProcess},
    {(unsigned char*)"BeaconInjectTemporaryProcess", (unsigned char*)BeaconInjectTemporaryProcess},
    {(unsigned char*)"BeaconCleanupProcess", (unsigned char*)BeaconCleanupProcess},
    {(unsigned char*)"toWideChar", (unsigned char*)toWideChar},
    {(unsigned char*)"BeaconInformation", (unsigned char*)BeaconInformation},
    {(unsigned char*)"BeaconAddValue", (unsigned char*)BeaconAddValue},
    {(unsigned char*)"BeaconGetValue", (unsigned char*)BeaconGetValue},
    {(unsigned char*)"BeaconRemoveValue", (unsigned char*)BeaconRemoveValue},
    {(unsigned char*)"BeaconDataStoreGetItem", (unsigned char*)BeaconDataStoreGetItem},
    {(unsigned char*)"BeaconDataStoreProtectItem", (unsigned char*)BeaconDataStoreProtectItem},
    {(unsigned char*)"BeaconDataStoreUnprotectItem", (unsigned char*)BeaconDataStoreUnprotectItem},
    {(unsigned char*)"BeaconDataStoreMaxEntries", (unsigned char*)BeaconDataStoreMaxEntries},
    {(unsigned char*)"BeaconGetCustomUserData", (unsigned char*)BeaconGetCustomUserData},
    {(unsigned char*)"LoadLibraryA", (unsigned char*)LoadLibraryA},
    {(unsigned char*)"GetProcAddress", (unsigned char*)GetProcAddress},
    {(unsigned char*)"GetModuleHandleA", (unsigned char*)GetModuleHandleA},
    {(unsigned char*)"FreeLibrary", (unsigned char*)FreeLibrary},
    {(unsigned char*)"__C_specific_handler", NULL}
};

uint32_t swap_endianess(uint32_t indata) {
    uint32_t testint = 0xaabbccdd;
    uint32_t outint = indata;
    if (((unsigned char*)&testint)[0] == 0xdd) {
        ((unsigned char*)&outint)[0] = ((unsigned char*)&indata)[3];
        ((unsigned char*)&outint)[1] = ((unsigned char*)&indata)[2];
        ((unsigned char*)&outint)[2] = ((unsigned char*)&indata)[1];
        ((unsigned char*)&outint)[3] = ((unsigned char*)&indata)[0];
    }
    return outint;
}

/* Output sink. When a Go callback is registered (DLL mode) output is streamed
 * to it with the Beacon callback type preserved, so binary data and file
 * downloads survive. When no callback is registered (standalone EXE) output is
 * accumulated into the global buffer for BeaconGetOutputData(). */
char* beacon_compatibility_output = NULL;
int beacon_compatibility_size = 0;
int beacon_compatibility_offset = 0;

static goCallback g_callback = NULL;

void BeaconSetCallback(goCallback callback) {
    g_callback = callback;
    printf("[COFFLoader] BeaconSetCallback callback=%p\n", (void*)callback);
}

void BeaconDataParse(datap* parser, char* buffer, int size) {
    if (parser == NULL || buffer == NULL) {
        return;
    }

    parser->original = buffer;
    parser->buffer = buffer;
    parser->length = size - 4;
    parser->size = size - 4;
    parser->buffer += 4;
    return;
}

char* BeaconDataPtr(datap* parser, int size) {
    char* ptr = NULL;
    if (parser == NULL || size < 0) {
        return NULL;
    }
    if (parser->length < size) {
        return NULL;
    }
    ptr = parser->buffer;
    parser->buffer += size;
    parser->length -= size;
    return ptr;
}

int BeaconDataInt(datap* parser) {
    if (parser == NULL) {
        return 0;
    }

    int32_t fourbyteint = 0;
    if (parser->length < 4) {
        return 0;
    }
    memcpy(&fourbyteint, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    return (int)fourbyteint;
}

short BeaconDataShort(datap* parser) {
    if (parser == NULL) {
        return 0;
    }

    int16_t retvalue = 0;
    if (parser->length < 2) {
        return 0;
    }
    memcpy(&retvalue, parser->buffer, 2);
    parser->buffer += 2;
    parser->length -= 2;
    return (short)retvalue;
}

int BeaconDataLength(datap* parser) {
    if (parser == NULL) {
        return 0;
    }

    return parser->length;
}

char* BeaconDataExtract(datap* parser, int* size) {
    if (parser == NULL) {
        return NULL;
    }

    uint32_t length = 0;
    char* outdata = NULL;
    /*Length prefixed binary blob, going to assume uint32_t for this.*/
    if (parser->length < 4) {
        return NULL;
    }
    memcpy(&length, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;

    /* Bounds check: a malformed BOF must not drive us out of range. */
    if ((uint32_t)parser->length < length) {
        return NULL;
    }

    outdata = parser->buffer;
    parser->length -= (int)length;
    parser->buffer += length;
    if (size != NULL) {
        *size = (int)length;
    }
    return outdata;
}

/* format API */

void BeaconFormatAlloc(formatp* format, int maxsz) {
    if (format == NULL) {
        return;
    }

    format->original = calloc(maxsz, 1);
    format->buffer = format->original;
    format->length = 0;
    format->size = maxsz;
    return;
}

void BeaconFormatReset(formatp* format) {
    if (format == NULL) {
        return;
    }

    if (format->original != NULL) {
        memset(format->original, 0, format->size);
    }
    format->buffer = format->original;
    format->length = 0;
    return;
}

void BeaconFormatFree(formatp* format) {
    if (format == NULL) {
        return;
    }
    if (format->original) {
        free(format->original);
        format->original = NULL;
    }
    format->buffer = NULL;
    format->length = 0;
    format->size = 0;
    return;
}

void BeaconFormatAppend(formatp* format, char* text, int len) {
    if (format == NULL || text == NULL || len < 0) {
        return;
    }
    if (format->original == NULL || format->buffer == NULL) {
        return;
    }

    /* Bounds check: never write past the allocated buffer. */
    if (len > format->size - format->length) {
        len = format->size - format->length;
    }
    if (len <= 0) {
        return;
    }

    memcpy(format->buffer, text, len);
    format->buffer += len;
    format->length += len;

    /* NUL-terminate if there is room left. */
    if (format->length < format->size) {
        format->buffer[0] = '\0';
    }
    return;
}

void BeaconFormatPrintf(formatp* format, char* fmt, ...) {
    if (format == NULL || fmt == NULL) {
        return;
    }
    if (format->original == NULL || format->buffer == NULL) {
        return;
    }

    va_list args;
    int length = 0;

    va_start(args, fmt);
    length = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    if (length < 0) {
        return;
    }

    /* Leave room for the terminating NUL. */
    if (length + 1 > format->size - format->length) {
        int remaining = format->size - format->length - 1;
        if (remaining <= 0) {
            return;
        }
        length = remaining;
    }

    va_start(args, fmt);
    (void)vsnprintf(format->buffer, length + 1, fmt, args);
    va_end(args);
    format->length += length;
    format->buffer += length;
    return;
}

char* BeaconFormatToString(formatp* format, int* size) {
    if (format == NULL || size == NULL) {
        return NULL;
    }

    *size = format->length;
    return format->original;
}

void BeaconFormatInt(formatp* format, int value) {
    if (format == NULL) {
        return;
    }

    uint32_t indata = value;
    uint32_t outdata = 0;
    if (format->length + 4 > format->size) {
        return;
    }
    outdata = swap_endianess(indata);
    memcpy(format->buffer, &outdata, 4);
    format->length += 4;
    format->buffer += 4;
    return;
}

/* Main output functions */

void BeaconPrintf(int type, char* fmt, ...) {
    if (fmt == NULL) {
        return;
    }

    printf("[COFFLoader] BeaconPrintf type=%d cb=%p\n", type, (void*)g_callback);

    va_list args;
    int length = 0;
    char* stackbuf = NULL;
    char* tempptr = NULL;

    va_start(args, fmt);
    length = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    if (length < 0) {
        return;
    }

    stackbuf = (char*)malloc((size_t)length + 1);
    if (stackbuf == NULL) {
        return;
    }
    va_start(args, fmt);
    (void)vsnprintf(stackbuf, (size_t)length + 1, fmt, args);
    va_end(args);

    if (g_callback != NULL) {
        g_callback(type, stackbuf, length);
        free(stackbuf);
        return;
    }

    /* Standalone mode: mirror to the console and accumulate. */
    printf("%s", stackbuf);

    tempptr = (char*)realloc(beacon_compatibility_output, beacon_compatibility_size + length + 1);
    if (tempptr == NULL) {
        free(stackbuf);
        return;
    }
    beacon_compatibility_output = tempptr;
    memcpy(beacon_compatibility_output + beacon_compatibility_offset, stackbuf, length);
    beacon_compatibility_offset += length;
    beacon_compatibility_size += length;
    beacon_compatibility_output[beacon_compatibility_offset] = '\0';
    free(stackbuf);
    return;
}

void BeaconOutput(int type, char* data, int len) {
    printf("[COFFLoader] BeaconOutput type=%d len=%d cb=%p\n", type, len, (void*)g_callback);
    if (data == NULL || len <= 0) {
        return;
    }

    if (g_callback != NULL) {
        /* Preserve the type + raw bytes. No strlen() anywhere: the buffer is
         * allowed to contain embedded NULs and arbitrary binary data. */
        g_callback(type, data, len);
        return;
    }

    /* Standalone mode: accumulate in the global buffer. */
    char* tempptr = (char*)realloc(beacon_compatibility_output, beacon_compatibility_size + len + 1);
    if (tempptr == NULL) {
        return;
    }
    beacon_compatibility_output = tempptr;
    memcpy(beacon_compatibility_output + beacon_compatibility_offset, data, len);
    beacon_compatibility_offset += len;
    beacon_compatibility_size += len;
    beacon_compatibility_output[beacon_compatibility_offset] = '\0';
    return;
}

BOOL BeaconDownload(const char* filename, const char* buffer, unsigned int length) {
    if (filename == NULL || (buffer == NULL && length != 0)) {
        return FALSE;
    }

    /* Emit the same CALLBACK_FILE / CALLBACK_FILE_WRITE / CALLBACK_FILE_CLOSE
     * framing that Cobalt Strike (and e.g. nanodump) uses for downloads:
     *   CALLBACK_FILE:        [u32be fileId][u32be fileLength][filename]
     *   CALLBACK_FILE_WRITE:  [u32be fileId][chunk]
     *   CALLBACK_FILE_CLOSE:  [u32be fileId]
     */
    static LONG fileIdCounter = 0;
    DWORD fileId = (DWORD)InterlockedIncrement(&fileIdCounter);

    size_t nameLen = strlen(filename);
    size_t hdrLen = 8 + nameLen;
    char* hdr = (char*)calloc(1, hdrLen);
    if (hdr == NULL) {
        return FALSE;
    }
    hdr[0] = (char)((fileId >> 24) & 0xFF);
    hdr[1] = (char)((fileId >> 16) & 0xFF);
    hdr[2] = (char)((fileId >> 8) & 0xFF);
    hdr[3] = (char)(fileId & 0xFF);
    hdr[4] = (char)((length >> 24) & 0xFF);
    hdr[5] = (char)((length >> 16) & 0xFF);
    hdr[6] = (char)((length >> 8) & 0xFF);
    hdr[7] = (char)(length & 0xFF);
    memcpy(hdr + 8, filename, nameLen);
    BeaconOutput(CALLBACK_FILE, hdr, (int)hdrLen);
    free(hdr);

    unsigned int sent = 0;
    while (sent < length) {
        unsigned int chunk = length - sent;
        if (chunk > 0x1000) {
            chunk = 0x1000;
        }
        char* cbuf = (char*)malloc(4 + chunk);
        if (cbuf == NULL) {
            return FALSE;
        }
        cbuf[0] = (char)((fileId >> 24) & 0xFF);
        cbuf[1] = (char)((fileId >> 16) & 0xFF);
        cbuf[2] = (char)((fileId >> 8) & 0xFF);
        cbuf[3] = (char)(fileId & 0xFF);
        memcpy(cbuf + 4, buffer + sent, chunk);
        BeaconOutput(CALLBACK_FILE_WRITE, cbuf, (int)(4 + chunk));
        free(cbuf);
        sent += chunk;
    }

    char closeBuf[4];
    closeBuf[0] = (char)((fileId >> 24) & 0xFF);
    closeBuf[1] = (char)((fileId >> 16) & 0xFF);
    closeBuf[2] = (char)((fileId >> 8) & 0xFF);
    closeBuf[3] = (char)(fileId & 0xFF);
    BeaconOutput(CALLBACK_FILE_CLOSE, closeBuf, 4);
    return TRUE;
}

/* Token Functions */

/* Stack of the thread tokens we displaced. Each BeaconUseToken() pushes the
 * token the thread was impersonating before the call (NULL if it was not
 * impersonating). BeaconRevertToken() pops and restores it. */
static HANDLE g_token_stack[BEACON_TOKEN_STACK_MAX];
static int    g_token_stack_depth = 0;

BOOL BeaconUseToken(HANDLE token) {
    HANDLE dupToken = NULL;
    TOKEN_TYPE tokenType = TokenPrimary;
    DWORD retLen = 0;
    HANDLE prevToken = NULL;

    if (token == NULL || token == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    if (!GetTokenInformation(token, TokenType, &tokenType, sizeof(tokenType), &retLen)) {
        return FALSE;
    }

    if (tokenType == TokenPrimary) {
        /* Primary tokens can't be assigned to a thread directly: duplicate them
         * down to an impersonation token. */
        if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                              TokenImpersonation, &dupToken)) {
            return FALSE;
        }
    }
    else {
        if (!DuplicateToken(token, SecurityImpersonation, &dupToken)) {
            return FALSE;
        }
    }

    /* Snapshot the current impersonation token so we can restore it. */
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_IMPERSONATE | TOKEN_QUERY, TRUE, &prevToken)) {
        prevToken = NULL;
    }

    if (!SetThreadToken(NULL, dupToken)) {
        CloseHandle(dupToken);
        return FALSE;
    }
    /* SetThreadToken assigned dupToken to this thread; we can drop our handle. */
    CloseHandle(dupToken);

    if (g_token_stack_depth < BEACON_TOKEN_STACK_MAX) {
        g_token_stack[g_token_stack_depth++] = prevToken;
    }
    else if (prevToken != NULL) {
        CloseHandle(prevToken);
    }

    return TRUE;
}

void BeaconRevertToken(void) {
    if (g_token_stack_depth > 0) {
        HANDLE prev = g_token_stack[--g_token_stack_depth];
        if (prev != NULL) {
            SetThreadToken(NULL, prev);
            CloseHandle(prev);
        }
        else {
            RevertToSelf();
        }
    }
    else {
        RevertToSelf();
    }
    return;
}

/* Revert every outstanding impersonation. Called by the loader after a BOF
 * finishes so an impersonating BOF can never leave the agent thread tokenized. */
void BeaconResetTokens(void) {
    while (g_token_stack_depth > 0) {
        HANDLE prev = g_token_stack[--g_token_stack_depth];
        if (prev != NULL) {
            SetThreadToken(NULL, prev);
            CloseHandle(prev);
        }
    }
    RevertToSelf();
    return;
}

BOOL BeaconIsAdmin(void) {
    HANDLE token = NULL;
    DWORD retLen = 0;
    TOKEN_ELEVATION elevation;
    BOOL isMember = FALSE;

    /* Primary check: split-token UAC elevation. */
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &retLen) &&
            elevation.TokenIsElevated) {
            CloseHandle(token);
            return TRUE;
        }
        CloseHandle(token);
    }

    /* Fallback: membership in BUILTIN\Administrators (covers services and
     * processes running without a split token). */
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminsSid = NULL;
    if (AllocateAndInitializeSid(&ntAuthority, 2,
                                 SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0, &adminsSid)) {
        if (CheckTokenMembership(NULL, adminsSid, &isMember) && isMember) {
            FreeSid(adminsSid);
            return TRUE;
        }
        FreeSid(adminsSid);
    }

    return FALSE;
}

/* Beacon Information */

void BeaconInformation(BEACON_INFO* info) {
    if (info == NULL) {
        return;
    }
    memset(info, 0, sizeof(*info));
    /* There is no Beacon here: report the loader's own module as the closest
     * thing to a "beacon base". No sleep mask / heap records to expose. */
    info->beacon_ptr = (char*)GetModuleHandleA(NULL);
    info->sleep_mask_ptr = NULL;
    info->sleep_mask_text_size = 0;
    info->sleep_mask_total_size = 0;
    info->sections = NULL;
    info->heap_records = NULL;
    memset(info->mask, 0, MASK_SIZE);
    return;
}

/* Key/Value store */

typedef struct _KV_ENTRY {
    char* key;
    void* value;
    struct _KV_ENTRY* next;
} KV_ENTRY;

static KV_ENTRY* g_kv_head = NULL;

static char* kv_strdup(const char* s) {
    size_t n;
    char* p;
    if (s == NULL) {
        return NULL;
    }
    n = strlen(s) + 1;
    p = (char*)malloc(n);
    if (p != NULL) {
        memcpy(p, s, n);
    }
    return p;
}

BOOL BeaconAddValue(const char* key, void* ptr) {
    KV_ENTRY* e;
    if (key == NULL || ptr == NULL) {
        return FALSE;
    }

    (void)BeaconRemoveValue(key); /* replace any existing entry */

    e = (KV_ENTRY*)calloc(1, sizeof(KV_ENTRY));
    if (e == NULL) {
        return FALSE;
    }
    e->key = kv_strdup(key);
    if (e->key == NULL) {
        free(e);
        return FALSE;
    }
    e->value = ptr;
    e->next = g_kv_head;
    g_kv_head = e;
    return TRUE;
}

void* BeaconGetValue(const char* key) {
    KV_ENTRY* e;
    if (key == NULL) {
        return NULL;
    }
    for (e = g_kv_head; e != NULL; e = e->next) {
        if (e->key != NULL && strcmp(e->key, key) == 0) {
            return e->value;
        }
    }
    return NULL;
}

BOOL BeaconRemoveValue(const char* key) {
    KV_ENTRY** pp;
    if (key == NULL) {
        return FALSE;
    }
    for (pp = &g_kv_head; *pp != NULL; pp = &(*pp)->next) {
        if ((*pp)->key != NULL && strcmp((*pp)->key, key) == 0) {
            KV_ENTRY* dead = *pp;
            *pp = dead->next;
            free(dead->key);
            free(dead);
            return TRUE;
        }
    }
    return FALSE;
}

/* Data Store */

static DATA_STORE_OBJECT g_data_store[BEACON_DATA_STORE_MAX_ENTRIES];

size_t BeaconDataStoreMaxEntries(void) {
    return BEACON_DATA_STORE_MAX_ENTRIES;
}

PDATA_STORE_OBJECT BeaconDataStoreGetItem(size_t index) {
    if (index >= BEACON_DATA_STORE_MAX_ENTRIES) {
        return NULL;
    }
    if (g_data_store[index].type == DATA_STORE_TYPE_EMPTY) {
        return NULL;
    }
    return &g_data_store[index];
}

void BeaconDataStoreProtectItem(size_t index) {
    if (index < BEACON_DATA_STORE_MAX_ENTRIES) {
        g_data_store[index].masked = TRUE;
    }
}

void BeaconDataStoreUnprotectItem(size_t index) {
    if (index < BEACON_DATA_STORE_MAX_ENTRIES) {
        g_data_store[index].masked = FALSE;
    }
}

/* Beacon User Data */

static char g_custom_user_data[32]; /* CS reserves a fixed 32-byte buffer */

char* BeaconGetCustomUserData(void) {
    return g_custom_user_data;
}

/* Injection/spawning related stuffs
 *
 * These functions are basic place holders, and if implemented into something
 * real should be just calling internal functions for your tools. */
void BeaconGetSpawnTo(BOOL x86, char* buffer, int length) {
    const char* tempBufferPath = NULL;
    size_t pathLen = 0;
    if (buffer == NULL || length <= 0) {
        return;
    }
    if (x86) {
        tempBufferPath = "C:\\Windows\\"X86PATH"\\"DEFAULTPROCESSNAME;
    }
    else {
        tempBufferPath = "C:\\Windows\\"X64PATH"\\"DEFAULTPROCESSNAME;
    }

    pathLen = strlen(tempBufferPath);
    if ((int)pathLen >= length) {
        return;
    }
    memcpy(buffer, tempBufferPath, pathLen);
    buffer[pathLen] = '\0';
    return;
}

BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * sInfo, PROCESS_INFORMATION * pInfo) {
    BOOL bSuccess = FALSE;
    (void)ignoreToken;
    if (x86) {
        bSuccess = CreateProcessA(NULL, (char*)"C:\\Windows\\"X86PATH"\\"DEFAULTPROCESSNAME, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, sInfo, pInfo);
    }
    else {
        bSuccess = CreateProcessA(NULL, (char*)"C:\\Windows\\"X64PATH"\\"DEFAULTPROCESSNAME, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, sInfo, pInfo);
    }
    return bSuccess;
}

void BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char * arg, int a_len) {
    /* Leaving this to be implemented by people needing/wanting it */
    (void)hProc; (void)pid; (void)payload; (void)p_len; (void)p_offset; (void)arg; (void)a_len;
    BeaconPrintf(CALLBACK_ERROR, "[COFFLoader] BeaconInjectProcess is not implemented (no injection backend)\n");
    return;
}

void BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len) {
    /* Leaving this to be implemented by people needing/wanting it */
    (void)pInfo; (void)payload; (void)p_len; (void)p_offset; (void)arg; (void)a_len;
    BeaconPrintf(CALLBACK_ERROR, "[COFFLoader] BeaconInjectTemporaryProcess is not implemented (no injection backend)\n");
    return;
}

void BeaconCleanupProcess(PROCESS_INFORMATION* pInfo) {
    if (pInfo != NULL) {
        (void)CloseHandle(pInfo->hThread);
        (void)CloseHandle(pInfo->hProcess);
    }
    return;
}

BOOL toWideChar(char* src, wchar_t* dst, int max) {
    int count;
    int written;
    if (src == NULL || dst == NULL || max <= 0) {
        return FALSE;
    }
    count = max / (int)sizeof(wchar_t);
    if (count <= 0) {
        return FALSE;
    }
    written = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, src, -1, dst, count);
    return written > 0;
}

/* __C_specific_handler lives in the CRT / ntdll, not kernel32.dll. Try the
 * usual homes so BOFs compiled with SEH unwind metadata can resolve it. */
void* BeaconResolveCSpecificHandler(void) {
    static const char* candidates[] = {
        "ntdll.dll", "vcruntime140.dll", "vcruntime140_1.dll",
        "msvcrt.dll", "ucrtbase.dll"
    };
    size_t i;
    for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        HMODULE h = GetModuleHandleA(candidates[i]);
        if (h == NULL) {
            h = LoadLibraryA(candidates[i]);
        }
        if (h != NULL) {
            FARPROC p = GetProcAddress(h, "__C_specific_handler");
            if (p != NULL) {
                return (void*)p;
            }
        }
    }
    return NULL;
}

char* BeaconGetOutputData(int *outsize) {
    if (outsize == NULL) {
        return NULL;
    }

    char* outdata = beacon_compatibility_output;
    *outsize = beacon_compatibility_size;
    beacon_compatibility_output = NULL;
    beacon_compatibility_size = 0;
    beacon_compatibility_offset = 0;
    return outdata;
}

#endif
