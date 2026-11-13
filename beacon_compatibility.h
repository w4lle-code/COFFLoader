/*
 * Cobalt Strike 4.X BOF compatibility layer
 * -----------------------------------------
 * The whole point of these files are to allow beacon object files built for CS
 * to run fine inside of other tools without recompiling.
 *
 * Built off of the beacon.h file provided to build for CS.
 */
#ifndef BEACON_COMPATIBILITY_H_
#define BEACON_COMPATIBILITY_H_

#include <stddef.h>

/* Callback shared with COFFLoader.h. The callback carries the Beacon output
 * type (CALLBACK_OUTPUT / CALLBACK_FILE / ...) together with the raw buffer and
 * its byte length, so binary output and file downloads survive intact. */
#ifndef GOCALLBACK_DEFINED
#define GOCALLBACK_DEFINED
typedef int (*goCallback)(int type, char * data, int len);
#endif

/* Number of internal symbols resolvable by process_symbol(). Keep in sync with
 * the InternalFunctions[] table in beacon_compatibility.c. */
#define BEACON_INTERNAL_FUNCTIONS_COUNT 39

extern unsigned char* InternalFunctions[BEACON_INTERNAL_FUNCTIONS_COUNT][2];

/* Structures as is in beacon.h */
typedef struct {
    char * original; /* the original buffer [so we can free it] */
    char * buffer;   /* current pointer into our buffer */
    int    length;   /* remaining length of data */
    int    size;     /* total size of this buffer */
} datap;

typedef struct {
    char * original; /* the original buffer [so we can free it] */
    char * buffer;   /* current pointer into our buffer */
    int    length;   /* remaining length of data */
    int    size;     /* total size of this buffer */
} formatp;

void    BeaconDataParse(datap * parser, char * buffer, int size);
char *  BeaconDataPtr(datap * parser, int size);
int     BeaconDataInt(datap * parser);
short   BeaconDataShort(datap * parser);
int     BeaconDataLength(datap * parser);
char *  BeaconDataExtract(datap * parser, int * size);

void    BeaconFormatAlloc(formatp * format, int maxsz);
void    BeaconFormatReset(formatp * format);
void    BeaconFormatFree(formatp * format);
void    BeaconFormatAppend(formatp * format, char * text, int len);
void    BeaconFormatPrintf(formatp * format, char * fmt, ...);
char *  BeaconFormatToString(formatp * format, int * size);
void    BeaconFormatInt(formatp * format, int value);

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_FILE        0x02
#define CALLBACK_FILE_WRITE  0x08
#define CALLBACK_FILE_CLOSE  0x09

void   BeaconPrintf(int type, char * fmt, ...);
void   BeaconOutput(int type, char * data, int len);
BOOL   BeaconDownload(const char * filename, const char * buffer, unsigned int length);

/* Token Functions */
BOOL   BeaconUseToken(HANDLE token);
void   BeaconRevertToken();
BOOL   BeaconIsAdmin();

/* Spawn+Inject Functions */
void   BeaconGetSpawnTo(BOOL x86, char * buffer, int length);
BOOL   BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * sInfo, PROCESS_INFORMATION * pInfo);
void   BeaconInjectProcess(HANDLE hProc, int pid, char * payload, int p_len, int p_offset, char * arg, int a_len);
void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION * pInfo, char * payload, int p_len, int p_offset, char * arg, int a_len);
void   BeaconCleanupProcess(PROCESS_INFORMATION * pInfo);

/* Utility Functions */
BOOL   toWideChar(char * src, wchar_t * dst, int max);
uint32_t swap_endianess(uint32_t indata);

/* Beacon Information (CS 4.9) */
typedef struct {
    char * ptr;
    size_t size;
} HEAP_RECORD;

#define MASK_SIZE 13

typedef struct {
    char * sleep_mask_ptr;
    DWORD  sleep_mask_text_size;
    DWORD  sleep_mask_total_size;
    char * beacon_ptr;
    DWORD * sections;
    HEAP_RECORD * heap_records;
    char   mask[MASK_SIZE];
} BEACON_INFO;

void   BeaconInformation(BEACON_INFO * info);

/* Key/Value store (CS 4.9) */
BOOL   BeaconAddValue(const char * key, void * ptr);
void * BeaconGetValue(const char * key);
BOOL   BeaconRemoveValue(const char * key);

/* Data Store (CS 4.9) */
#define DATA_STORE_TYPE_EMPTY         0
#define DATA_STORE_TYPE_GENERAL_FILE  1

typedef struct {
    int      type;
    DWORD64  hash;
    BOOL     masked;
    char *   buffer;
    size_t   length;
} DATA_STORE_OBJECT, *PDATA_STORE_OBJECT;

PDATA_STORE_OBJECT BeaconDataStoreGetItem(size_t index);
void   BeaconDataStoreProtectItem(size_t index);
void   BeaconDataStoreUnprotectItem(size_t index);
size_t BeaconDataStoreMaxEntries(void);

/* Beacon User Data (CS 4.9) */
char * BeaconGetCustomUserData(void);

/* Internal loader hooks */
void   BeaconSetCallback(goCallback callback);
void   BeaconResetTokens(void);
void * BeaconResolveCSpecificHandler(void);

char * BeaconGetOutputData(int *outsize);
#endif
