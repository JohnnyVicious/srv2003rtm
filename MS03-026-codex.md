# MS03-026 (CVE-2003-0352, “Blaster”) Code Location Notes

## Overview
MS03-026 is the RPC/DCOM activation stack overflow that Blaster exploited on TCP/135. The attack drives the DCOM `IActivation` (uuid `4d9f4ab8-7d1c-11cf-861e-0020af6e7c57`) interface implemented by `rpcss` and overflows a small stack buffer while parsing the machine name portion of a client-supplied UNC path during remote activation.

## Call Path (DCOM Remote Activation)
1. **RPC contract**: `com/ole32/idl/public/remact.idl` defines `IActivation::RemoteActivation` with unconstrained string params (`pwszObjectName`, `pObjectStorage`) and large ranges (`Interfaces`/`cRequestedProtseqs` up to 0x8000).
   ```c
   error_status_t RemoteActivation(
       [in] handle_t hRpc,
       [in] ORPCTHIS *ORPCthis,
       [out] ORPCTHAT *ORPCthat,
       [in] GUID *Clsid,
       [in, string, unique] WCHAR *pwszObjectName,   // user-controlled path
       [in, unique] MInterfacePointer *pObjectStorage,
       [in] DWORD ClientImpLevel,
       [in] DWORD Mode,
       [in,range(1,MAX_REQUESTED_INTERFACES)] DWORD Interfaces,
       [in,unique,size_is(Interfaces)] IID *pIIDs,
       ...
   );
   ```
2. **Server entry point**: `_RemoteActivation` in `com/ole32/dcomss/olescm/remactif.cxx` (opnum serviced by `rpcss`) forwards the user-supplied object name to path normalization helpers:
   ```c++
   error_status_t _RemoteActivation(..., WCHAR *pwszObjectName, ...)
   {
       ...
       if (pwszObjectName) {
           *phr = GetServerPath(pwszObjectName, &pwszObjectName);
           if (FAILED(*phr)) goto exit_oldremote;
       }
       ...
   }
   ```
3. **Vulnerable parsing**: `GetServerPath` (`com/ole32/dcomss/olescm/remactif.cxx:390-467`) handles UNC inputs and calls `GetMachineName` with a tiny stack buffer:
   ```c++
   if ((pwszPath[0] == L'\\') && (pwszPath[1] == L'\\')) {
       WCHAR wszMachineName[MAX_COMPUTERNAME_LENGTH+1]; // 16 wide chars
       hr = GetMachineName(pwszPath, wszMachineName);
       ...
   }
   ```
   `GetMachineName` (`com/ole32/dcomss/olescm/actmisc.cxx:18-128`) then copies the host portion of the UNC path into that 16-character buffer without any length check:
   ```c++
   LPWSTR pwszTemp = pwszPath + 2;    // skip leading "\\"
   pwszServerName = wszMachineName;   // dest = 16 wide chars
   while (*pwszTemp != L'\\')
       *pwszServerName++ = *pwszTemp++;   // no bounds check
   *pwszServerName = 0;
   ```
   A host component longer than 15 characters overflows the 16-wide-char buffer on the stack of `rpcss`.

## Trigger Summary
Send a `RemoteActivation` request (DCOM bind to uuid `4d9f4ab8-7d1c-11cf-861e-0020af6e7c57`, opnum `RemoteActivation`) with `pwszObjectName` set to a UNC path whose machine-name component far exceeds 15 characters (e.g., `\\AAAA...A\share\file`). `GetMachineName` copies that host name into a 16-wide-char stack buffer, overflowing stack state in the SYSTEM-privileged `rpcss` service.

## Fix Considerations
- Enforce `MAX_COMPUTERNAME_LENGTH` when copying the host component: use `lstrcpynW(wszMachineName, pwszPath + 2, MAX_COMPUTERNAME_LENGTH + 1)` and/or terminate at the first backslash without overrunning the 16-wide-char buffer.
- Reject UNC inputs whose server name exceeds 15 characters before calling `GetMachineName`; optionally cap overall path length as well.
- Keep the RPC IDL expectations and server-side bounds aligned so attacker-controlled strings can’t bypass internal buffer limits.
