# MS08-067 (CVE-2008-4250) Code Location Notes

## Overview
The MS08-067 vulnerability is a stack-based overflow in the Server Service canonicalization path invoked over RPC (`srvsvc`). An attacker sends a crafted `NetprPathCanonicalize` request to overflow a fixed-size stack buffer during path normalization, leading to remote code execution in the `svchost.exe` hosting `lanmanserver`.

## Call Path
1. **RPC interface**: `ds/netapi/svcdlls/srvsvc/idl/srvsvc.idl` (`uuid 4B324FC8-1670-01D3-1278-5A47BF6EE188`, version 3.0). The method definition allows `OutbufLen` up to 64,000 bytes:
   ```c
   NET_API_STATUS NetprPathCanonicalize(
       [in,string,unique] SRVSVC_HANDLE ServerName,
       [in,string]        LPTSTR        PathName,
       [out,size_is(OutbufLen)] LPBYTE  Outbuf,
       [in,range(0, 64000)] DWORD       OutbufLen,
       [in,string]        LPTSTR        Prefix,
       [in,out]           LPDWORD       PathType,
       [in]               DWORD         Flags
   );
   ```
2. **Server stub**: `ds/netapi/svcdlls/srvsvc/server/canon.c` forwards directly to the worker without additional validation:
   ```c
   return NetpwPathCanonicalize(PathName, Outbuf, OutbufLen, Prefix, PathType, Flags);
   ```
3. **Worker wrapper**: `ds/netapi/netlib/pathcan.c:121-164` validates `PathType` and the caller’s output buffer length, then calls the canonicalizer:
   ```c
   rc = CanonicalizePathName(Prefix, PathName, Outbuf, OutbufLen, NULL);
   ```
4. **Vulnerable canonicalizer**: `ds/netapi/netlib/canon.c:165-213`.
   ```c
   TCHAR pathBuffer[MAX_PATH*2 + 1];
   ...
   if (ARGUMENT_PRESENT(PathPrefix)) {
       prefixLen = STRLEN(PathPrefix);
       if (prefixLen) {
           STRCPY(pathBuffer, PathPrefix);
           if (!IS_PATH_SEPARATOR(pathBuffer[prefixLen - 1])) {
               STRCAT(pathBuffer, TEXT("\\"));
               ++prefixLen;
           }
           if (IS_PATH_SEPARATOR(*PathName)) {
               ++PathName;
           }
       }
   }
   pathLen = STRLEN(PathName);
   if (pathLen + prefixLen > MAX_PATH*2 - 1) {
       return ERROR_INVALID_NAME;
   }
   STRCAT(pathBuffer, PathName);  // unchecked relative to pathBuffer size
   ...
   if (pathLen > BufferSize) return NERR_BufTooSmall;
   STRCPY(Buffer, pathBuffer);
   ```

## Flaw Detail
- `pathBuffer` is a fixed stack buffer (`MAX_PATH*2+1` wchar/char units) with no bounds check when concatenating `PathPrefix` + `PathName`. The code only checks `pathLen + prefixLen > MAX_PATH*2 - 1` **before** concatenation and assumes the earlier `STRCPY/STRCAT` won’t overrun, but `prefixLen` is taken from untrusted `PathPrefix` without ensuring it fits in `pathBuffer` (only checked against `MAX_PATH*2`, not `MAX_PATH*2 - pathLen`). A long `Prefix` or combined `Prefix`+`PathName` can overflow `pathBuffer` before the length guard triggers.
- The RPC interface accepts large strings (up to 64k) and runs under `svchost.exe` with SYSTEM privileges, so the overflow enables remote code execution.

## Trigger Conditions (conceptual)
- Send `NetprPathCanonicalize` with a very long `Prefix` (or `PathName`) such that `STRCAT` overflows `pathBuffer` before the length check or during macro conversion. The attack leverages the gap between the stack buffer size and the permitted RPC input size.

## Fix Approaches (historical)
- Use safe concatenation that enforces the `pathBuffer` bound (e.g., check `prefixLen >= ARRAYSIZE(pathBuffer)` and `pathLen + prefixLen < ARRAYSIZE(pathBuffer)` before any `STRCAT`).
- Reject inputs exceeding `MAX_PATH` before copying, or allocate dynamically sized buffers matching `OutbufLen`.
- Apply equivalent fixes in the down-level worker and ensure the RPC IDL length aligns with internal buffer limits.
