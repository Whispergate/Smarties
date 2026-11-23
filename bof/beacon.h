/*
 * Beacon Object Files (BOF)
 * -------------------------
 * A Beacon Object File is a light-weight post exploitation tool that runs
 * with Beacon's inline-execute command.
 *
 * Cobalt Strike 4.x / EmeraldStrike compatible beacon.h
 *
 * This header matches the exact struct layouts, function signatures, and
 * callback constants used by EmeraldStrike's COFF loader (coff_loader.cc)
 * and fork-and-run BOF bootstrap (bof_bootstrap.cc).
 *
 * DFR (Dynamic Function Resolution) declarations for Windows APIs used by
 * the Smarties BOF are appended after the standard Beacon API section.
 */
#ifndef _BEACON_H_
#define _BEACON_H_
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/* data API */
typedef struct {
	char * original; /* the original buffer [so we can free it] */
	char * buffer;   /* current pointer into our buffer */
	int    length;   /* remaining length of data */
	int    size;     /* total size of this buffer */
} datap;

DECLSPEC_IMPORT void    BeaconDataParse(datap * parser, char * buffer, int size);
DECLSPEC_IMPORT char *  BeaconDataPtr(datap * parser, int size);
DECLSPEC_IMPORT int     BeaconDataInt(datap * parser);
DECLSPEC_IMPORT short   BeaconDataShort(datap * parser);
DECLSPEC_IMPORT int     BeaconDataLength(datap * parser);
DECLSPEC_IMPORT char *  BeaconDataExtract(datap * parser, int * size);

/* format API */
typedef struct {
	char * original; /* the original buffer [so we can free it] */
	char * buffer;   /* current pointer into our buffer */
	int    length;   /* remaining length of data */
	int    size;     /* total size of this buffer */
} formatp;

DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp * format, int maxsz);
DECLSPEC_IMPORT void    BeaconFormatReset(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatAppend(formatp * format, const char * text, int len);
DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp * format, const char * fmt, ...);
DECLSPEC_IMPORT char *  BeaconFormatToString(formatp * format, int * size);
DECLSPEC_IMPORT void    BeaconFormatFree(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatInt(formatp * format, int value);

/* Output Functions */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d
#define CALLBACK_CUSTOM      0x1000
#define CALLBACK_CUSTOM_LAST 0x13ff

DECLSPEC_IMPORT void   BeaconOutput(int type, const char * data, int len);
DECLSPEC_IMPORT void   BeaconPrintf(int type, const char * fmt, ...);
DECLSPEC_IMPORT BOOL   BeaconDownload(const char * filename, const char* buffer, unsigned int length);

/* Token Functions */
DECLSPEC_IMPORT BOOL   BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void   BeaconRevertToken();
DECLSPEC_IMPORT BOOL   BeaconIsAdmin();

/* Spawn+Inject Functions */
DECLSPEC_IMPORT void   BeaconGetSpawnTo(BOOL x86, char * buffer, int length);
DECLSPEC_IMPORT void   BeaconInjectProcess(HANDLE hProc, int pid, char * payload, int p_len, int p_offset, char * arg, int a_len);
DECLSPEC_IMPORT void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION * pInfo, char * payload, int p_len, int p_offset, char * arg, int a_len);
DECLSPEC_IMPORT BOOL   BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * si, PROCESS_INFORMATION * pInfo);
DECLSPEC_IMPORT void   BeaconCleanupProcess(PROCESS_INFORMATION * pInfo);

/* Utility Functions */
DECLSPEC_IMPORT BOOL   toWideChar(char * src, wchar_t * dst, int max);

/* Beacon Information */
typedef struct {
	char * ptr;
	size_t size;
} HEAP_RECORD;
#define MASK_SIZE 13

typedef enum {
	PURPOSE_EMPTY,
	PURPOSE_GENERIC_BUFFER,
	PURPOSE_BEACON_MEMORY,
	PURPOSE_SLEEPMASK_MEMORY,
	PURPOSE_BOF_MEMORY,
	PURPOSE_UDC2_MEMORY,
	PURPOSE_USER_DEFINED_MEMORY = 1000
} ALLOCATED_MEMORY_PURPOSE;

typedef enum {
	LABEL_EMPTY,
	LABEL_BUFFER,
	LABEL_PEHEADER,
	LABEL_TEXT,
	LABEL_RDATA,
	LABEL_DATA,
	LABEL_PDATA,
	LABEL_RELOC,
	LABEL_USER_DEFINED = 1000
} ALLOCATED_MEMORY_LABEL;

typedef enum {
	METHOD_UNKNOWN,
	METHOD_VIRTUALALLOC,
	METHOD_HEAPALLOC,
	METHOD_MODULESTOMP,
	METHOD_NTMAPVIEW,
	METHOD_USER_DEFINED = 1000,
} ALLOCATED_MEMORY_ALLOCATION_METHOD;

typedef struct _HEAPALLOC_INFO {
	PVOID HeapHandle;
	BOOL  DestroyHeap;
} HEAPALLOC_INFO, *PHEAPALLOC_INFO;

typedef struct _MODULESTOMP_INFO {
	HMODULE ModuleHandle;
} MODULESTOMP_INFO, *PMODULESTOMP_INFO;

typedef union _ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION {
	HEAPALLOC_INFO HeapAllocInfo;
	MODULESTOMP_INFO ModuleStompInfo;
	PVOID Custom;
} ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION, *PALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION;

typedef struct _ALLOCATED_MEMORY_CLEANUP_INFORMATION {
	BOOL Cleanup;
	ALLOCATED_MEMORY_ALLOCATION_METHOD AllocationMethod;
	ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION AdditionalCleanupInformation;
} ALLOCATED_MEMORY_CLEANUP_INFORMATION, *PALLOCATED_MEMORY_CLEANUP_INFORMATION;

typedef struct _ALLOCATED_MEMORY_SECTION {
	ALLOCATED_MEMORY_LABEL Label;
	PVOID  BaseAddress;
	SIZE_T VirtualSize;
	DWORD  CurrentProtect;
	DWORD  PreviousProtect;
	BOOL   MaskSection;
	DWORD  DripLoadPageSize;
} ALLOCATED_MEMORY_SECTION, *PALLOCATED_MEMORY_SECTION;

typedef struct _ALLOCATED_MEMORY_REGION {
	ALLOCATED_MEMORY_PURPOSE Purpose;
	PVOID  AllocationBase;
	SIZE_T RegionSize;
	DWORD Type;
	DWORD DripLoadAllocationGranularity;
	ALLOCATED_MEMORY_SECTION Sections[8];
	ALLOCATED_MEMORY_CLEANUP_INFORMATION CleanupInformation;
} ALLOCATED_MEMORY_REGION, *PALLOCATED_MEMORY_REGION;

typedef struct {
	ALLOCATED_MEMORY_REGION AllocatedMemoryRegions[6];
} ALLOCATED_MEMORY, *PALLOCATED_MEMORY;

typedef struct {
	unsigned int version;
	char  * sleep_mask_ptr;
	DWORD   sleep_mask_text_size;
	DWORD   sleep_mask_total_size;
	char  * beacon_ptr;
	HEAP_RECORD * heap_records;
	char    mask[MASK_SIZE];
	ALLOCATED_MEMORY allocatedMemory;
} BEACON_INFO, *PBEACON_INFO;

DECLSPEC_IMPORT BOOL   BeaconInformation(PBEACON_INFO info);

/* Key/Value store functions */
DECLSPEC_IMPORT BOOL BeaconAddValue(const char * key, void * ptr);
DECLSPEC_IMPORT void * BeaconGetValue(const char * key);
DECLSPEC_IMPORT BOOL BeaconRemoveValue(const char * key);

/* Beacon Data Store functions */
#define DATA_STORE_TYPE_EMPTY 0
#define DATA_STORE_TYPE_GENERAL_FILE 1

typedef struct {
	int type;
	DWORD64 hash;
	BOOL masked;
	char* buffer;
	size_t length;
} DATA_STORE_OBJECT, *PDATA_STORE_OBJECT;

DECLSPEC_IMPORT PDATA_STORE_OBJECT BeaconDataStoreGetItem(size_t index);
DECLSPEC_IMPORT void BeaconDataStoreProtectItem(size_t index);
DECLSPEC_IMPORT void BeaconDataStoreUnprotectItem(size_t index);
DECLSPEC_IMPORT size_t BeaconDataStoreMaxEntries();

/* Beacon User Data functions */
DECLSPEC_IMPORT char * BeaconGetCustomUserData();

/* Beacon Syscall API */
typedef struct {
	PVOID fnAddr;
	PVOID jmpAddr;
	DWORD sysnum;
} SYSCALL_API_ENTRY, *PSYSCALL_API_ENTRY;

typedef struct {
	SYSCALL_API_ENTRY ntAllocateVirtualMemory;
	SYSCALL_API_ENTRY ntProtectVirtualMemory;
	SYSCALL_API_ENTRY ntFreeVirtualMemory;
	SYSCALL_API_ENTRY ntGetContextThread;
	SYSCALL_API_ENTRY ntSetContextThread;
	SYSCALL_API_ENTRY ntResumeThread;
	SYSCALL_API_ENTRY ntCreateThreadEx;
	SYSCALL_API_ENTRY ntOpenProcess;
	SYSCALL_API_ENTRY ntOpenThread;
	SYSCALL_API_ENTRY ntClose;
	SYSCALL_API_ENTRY ntCreateSection;
	SYSCALL_API_ENTRY ntMapViewOfSection;
	SYSCALL_API_ENTRY ntUnmapViewOfSection;
	SYSCALL_API_ENTRY ntQueryVirtualMemory;
	SYSCALL_API_ENTRY ntDuplicateObject;
	SYSCALL_API_ENTRY ntReadVirtualMemory;
	SYSCALL_API_ENTRY ntWriteVirtualMemory;
	SYSCALL_API_ENTRY ntReadFile;
	SYSCALL_API_ENTRY ntWriteFile;
	SYSCALL_API_ENTRY ntCreateFile;
	SYSCALL_API_ENTRY ntQueueApcThread;
	SYSCALL_API_ENTRY ntCreateProcess;
	SYSCALL_API_ENTRY ntOpenProcessToken;
	SYSCALL_API_ENTRY ntTestAlert;
	SYSCALL_API_ENTRY ntSuspendProcess;
	SYSCALL_API_ENTRY ntResumeProcess;
	SYSCALL_API_ENTRY ntQuerySystemInformation;
	SYSCALL_API_ENTRY ntQueryDirectoryFile;
	SYSCALL_API_ENTRY ntSetInformationProcess;
	SYSCALL_API_ENTRY ntSetInformationThread;
	SYSCALL_API_ENTRY ntQueryInformationProcess;
	SYSCALL_API_ENTRY ntQueryInformationThread;
	SYSCALL_API_ENTRY ntOpenSection;
	SYSCALL_API_ENTRY ntAdjustPrivilegesToken;
	SYSCALL_API_ENTRY ntDeviceIoControlFile;
	SYSCALL_API_ENTRY ntWaitForMultipleObjects;
} SYSCALL_API, *PSYSCALL_API;

typedef struct {
	PVOID rtlDosPathNameToNtPathNameUWithStatusAddr;
	PVOID rtlFreeHeapAddr;
	PVOID rtlGetProcessHeapAddr;
} RTL_API, *PRTL_API;

typedef struct {
	SYSCALL_API syscalls;
	RTL_API     rtls;
} BEACON_SYSCALLS, *PBEACON_SYSCALLS;

DECLSPEC_IMPORT BOOL BeaconGetSyscallInformation(PBEACON_SYSCALLS info, SIZE_T infoSize, BOOL resolveIfNotInitialized);

DECLSPEC_IMPORT LPVOID BeaconVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT LPVOID BeaconVirtualAllocEx(HANDLE processHandle, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT BOOL BeaconVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
DECLSPEC_IMPORT BOOL BeaconVirtualProtectEx(HANDLE processHandle, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
DECLSPEC_IMPORT BOOL BeaconVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
DECLSPEC_IMPORT BOOL BeaconGetThreadContext(HANDLE threadHandle, PCONTEXT threadContext);
DECLSPEC_IMPORT BOOL BeaconSetThreadContext(HANDLE threadHandle, PCONTEXT threadContext);
DECLSPEC_IMPORT DWORD BeaconResumeThread(HANDLE threadHandle);
DECLSPEC_IMPORT HANDLE BeaconOpenProcess(DWORD desiredAccess, BOOL inheritHandle, DWORD processId);
DECLSPEC_IMPORT HANDLE BeaconOpenThread(DWORD desiredAccess, BOOL inheritHandle, DWORD threadId);
DECLSPEC_IMPORT BOOL BeaconCloseHandle(HANDLE object);
DECLSPEC_IMPORT BOOL BeaconUnmapViewOfFile(LPCVOID baseAddress);
DECLSPEC_IMPORT SIZE_T BeaconVirtualQuery(LPCVOID address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T length);
DECLSPEC_IMPORT BOOL BeaconDuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
DECLSPEC_IMPORT BOOL BeaconReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
DECLSPEC_IMPORT BOOL BeaconWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);

DECLSPEC_IMPORT VOID BeaconDisableBeaconGate();
DECLSPEC_IMPORT VOID BeaconEnableBeaconGate();
DECLSPEC_IMPORT VOID BeaconDisableBeaconGateMasking();
DECLSPEC_IMPORT VOID BeaconEnableBeaconGateMasking();

#define DLL_BEACON_USER_DATA 0x0d
#define BEACON_USER_DATA_CUSTOM_SIZE 32
typedef struct {
	unsigned int version;
	PSYSCALL_API syscalls;
	char         custom[BEACON_USER_DATA_CUSTOM_SIZE];
	PRTL_API     rtls;
	PALLOCATED_MEMORY allocatedMemory;
} USER_DATA, * PUSER_DATA;

/* ================================================================
 *  DYNAMIC FUNCTION RESOLUTION (DFR) DECLARATIONS
 *
 *  EmeraldStrike's COFF loader splits on '$', appends ".dll" to
 *  the module name, then calls LoadLibraryA + GetProcAddress.
 * ================================================================ */

/* ---- KERNEL32 ---- */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT void   WINAPI KERNEL32$SetLastError(DWORD);
DECLSPEC_IMPORT int    WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT int    WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$FreeLibrary(HMODULE);

/* ---- MSVCRT ---- */
DECLSPEC_IMPORT void * WINAPI MSVCRT$calloc(size_t, size_t);
DECLSPEC_IMPORT void   WINAPI MSVCRT$free(void *);
DECLSPEC_IMPORT void * WINAPI MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void * WINAPI MSVCRT$memcpy(void *, const void *, size_t);
DECLSPEC_IMPORT void * WINAPI MSVCRT$memset(void *, int, size_t);
DECLSPEC_IMPORT int    WINAPI MSVCRT$strcmp(const char *, const char *);
DECLSPEC_IMPORT int    WINAPI MSVCRT$_stricmp(const char *, const char *);
DECLSPEC_IMPORT int    WINAPI MSVCRT$_wcsicmp(const wchar_t *, const wchar_t *);
DECLSPEC_IMPORT size_t WINAPI MSVCRT$strlen(const char *);
DECLSPEC_IMPORT size_t WINAPI MSVCRT$wcslen(const wchar_t *);
DECLSPEC_IMPORT char * WINAPI MSVCRT$strcpy(char *, const char *);
DECLSPEC_IMPORT wchar_t * WINAPI MSVCRT$wcscpy(wchar_t *, const wchar_t *);
DECLSPEC_IMPORT char * WINAPI MSVCRT$strcat(char *, const char *);
DECLSPEC_IMPORT wchar_t * WINAPI MSVCRT$wcscat(wchar_t *, const wchar_t *);
DECLSPEC_IMPORT char * WINAPI MSVCRT$strstr(const char *, const char *);
DECLSPEC_IMPORT wchar_t * WINAPI MSVCRT$wcsstr(const wchar_t *, const wchar_t *);
DECLSPEC_IMPORT int    WINAPI MSVCRT$_snprintf(char *, size_t, const char *, ...);
DECLSPEC_IMPORT wchar_t * WINAPI MSVCRT$wcschr(const wchar_t *, wchar_t);
DECLSPEC_IMPORT char * WINAPI MSVCRT$strchr(const char *, int);
DECLSPEC_IMPORT int    WINAPI MSVCRT$atoi(const char *);

/* ---- CRYPT32 ---- */
DECLSPEC_IMPORT HCERTSTORE WINAPI CRYPT32$CertOpenSystemStoreW(HCRYPTPROV_LEGACY, LPCWSTR);
DECLSPEC_IMPORT BOOL       WINAPI CRYPT32$CertCloseStore(HCERTSTORE, DWORD);
DECLSPEC_IMPORT PCCERT_CONTEXT WINAPI CRYPT32$CertEnumCertificatesInStore(HCERTSTORE, PCCERT_CONTEXT);
DECLSPEC_IMPORT BOOL       WINAPI CRYPT32$CertGetCertificateContextProperty(PCCERT_CONTEXT, DWORD, void*, DWORD*);
DECLSPEC_IMPORT PCCERT_CONTEXT WINAPI CRYPT32$CertDuplicateCertificateContext(PCCERT_CONTEXT);
DECLSPEC_IMPORT BOOL       WINAPI CRYPT32$CertFreeCertificateContext(PCCERT_CONTEXT);
DECLSPEC_IMPORT DWORD      WINAPI CRYPT32$CertGetNameStringW(PCCERT_CONTEXT, DWORD, DWORD, void*, LPWSTR, DWORD);
DECLSPEC_IMPORT DWORD      WINAPI CRYPT32$CertGetNameStringA(PCCERT_CONTEXT, DWORD, DWORD, void*, LPSTR, DWORD);
DECLSPEC_IMPORT BOOL       WINAPI CRYPT32$CryptDecodeObjectEx(DWORD, LPCSTR, const BYTE*, DWORD, DWORD, PCRYPT_DECODE_PARA, void*, DWORD*);

/* ---- ADVAPI32 ---- */
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$CredMarshalCredentialW(DWORD, PVOID, LPWSTR*);
DECLSPEC_IMPORT void   WINAPI ADVAPI32$CredFree(PVOID);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$GetUserNameW(LPWSTR, LPDWORD);

/* ---- SECUR32 ---- */
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$AcquireCredentialsHandleW(
    LPWSTR, LPWSTR, ULONG, PLUID, PVOID, SEC_GET_KEY_FN, PVOID, PCredHandle, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$InitializeSecurityContextW(
    PCredHandle, PCtxtHandle, LPWSTR, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$FreeCredentialsHandle(PCredHandle);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$DeleteSecurityContext(PCtxtHandle);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$FreeContextBuffer(PVOID);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$LsaConnectUntrusted(PHANDLE);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$LsaDeregisterLogonProcess(HANDLE);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$LsaLookupAuthenticationPackage(HANDLE, PVOID, PULONG);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$LsaCallAuthenticationPackage(HANDLE, ULONG, PVOID, ULONG, PVOID*, PULONG, PNTSTATUS);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$LsaFreeReturnBuffer(PVOID);

/* ---- WINHTTP ---- */
DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpOpen(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpConnect(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpOpenRequest(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
DECLSPEC_IMPORT BOOL      WINAPI WINHTTP$WinHttpSendRequest(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
DECLSPEC_IMPORT BOOL      WINAPI WINHTTP$WinHttpReceiveResponse(HINTERNET, LPVOID);
DECLSPEC_IMPORT BOOL      WINAPI WINHTTP$WinHttpQueryHeaders(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
DECLSPEC_IMPORT BOOL      WINAPI WINHTTP$WinHttpCloseHandle(HINTERNET);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // _BEACON_H_
