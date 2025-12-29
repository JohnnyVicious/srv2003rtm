# MS06-040 (CVE-2006-3439, "Wargbot") Code Location Notes

## Overview
Server Service exposes `NetprPathCanonicalize` over `srvsvc` RPC; the worker `CanonicalizePathName` builds paths in a fixed 521-character stack buffer (`MAX_PATH*2+1`). The RPC contract permits up to 64KB of caller-controlled path/prefix data, and the function concatenates it with `STRCPY`/`STRCAT` before enforcing the internal `MAX_PATH*2` limit, enabling a stack overwrite. This is the same canonicalization path later abused by MS08-067.

## Call Path (RPC to Path Canonicalization)
1. **RPC interface** – `ds/netapi/svcdlls/srvsvc/idl/srvsvc.idl:896-913`  
   ```c
   NET_API_STATUS NetprPathCanonicalize(
       [in,string,unique] SRVSVC_HANDLE ServerName,
       [in,string] LPTSTR PathName,
       [out,size_is(OutbufLen)] LPBYTE Outbuf,
       [in,range(0, 64000)] DWORD OutbufLen,
       [in,string] LPTSTR Prefix,
       [in,out] LPDWORD PathType,
       [in] DWORD Flags);
   ```  
   RPC accepts up to 64KB for the output buffer and unconstrained strings for `PathName`/`Prefix`, mismatching the 521-character local buffer.
2. **Server-side stub** – `ds/netapi/svcdlls/srvsvc/server/canon.c:64-109`  
   ```c
   return NetpwPathCanonicalize(PathName, Outbuf, OutbufLen, Prefix, PathType, Flags);
   ```  
   No validation; forwards attacker-controlled strings directly to the worker.
3. **Wrapper** – `ds/netapi/netlib/pathcan.c:57-164`  
   ```c
   if (OutbufLen == 0) return NERR_BufTooSmall;
   *Outbuf = TCHAR_EOS;
   rc = CanonicalizePathName(Prefix, PathName, Outbuf, OutbufLen, NULL);
   ```  
   Enforces only zero-length output, leaving path length to the canonicalizer.
4. **Vulnerable canonicalizer** – `ds/netapi/netlib/canon.c:165-214`  
   ```c
   TCHAR pathBuffer[MAX_PATH*2 + 1];              // 521 chars on the stack
   ...
   prefixLen = STRLEN(PathPrefix);
   if (prefixLen > MAX_PATH*2) return ERROR_INVALID_NAME;
   STRCPY(pathBuffer, PathPrefix);                // no bound on copy
   if (!IS_PATH_SEPARATOR(pathBuffer[prefixLen-1])) {
       STRCAT(pathBuffer, TEXT("\\"));            // overflows when prefixLen==MAX_PATH*2
       ++prefixLen;
   }
   pathLen = STRLEN(PathName);
   if (pathLen + prefixLen > MAX_PATH*2 - 1) return ERROR_INVALID_NAME;
   STRCAT(pathBuffer, PathName);                  // unchecked relative to 521-char buffer
   ```
   The manual checks cap lengths at `MAX_PATH*2`, but the added slash and unbounded copies can write past `pathBuffer` before the combined-length guard triggers. Inputs up to 64KB from RPC make the overflow reachable. This code is identical to the path later patched in MS08-067.
5. **Path macro processing** – `ds/netapi/netlib/canon.c:416-519`  
   Works in-place on the same stack buffer (`STRCPY` moves during `\..` and `\.` removal) with no further bounds checks, so any prior overrun corrupts control data during these extra copies.

## Trigger Summary
Bind to `srvsvc` (`uuid 4b324fc8-1670-01d3-1278-5a47bf6ee188`, `ncacn_np:\\pipe\\srvsvc`) and invoke `NetprPathCanonicalize` with a `Prefix` (or combined `Prefix`+`PathName`) at or near `MAX_PATH*2` characters and no trailing slash. The stub copies it with `STRCPY`, appends a slash with `STRCAT`, and processes the path in the 521-character stack buffer before returning an error, overwriting stack state and allowing code execution in the Server Service `svchost`.

## Fix Considerations
- Enforce `ARRAYSIZE(pathBuffer)` before any copy/concatenation; reject or truncate when `prefixLen + 1` or `prefixLen + pathLen` exceeds the buffer (accounting for the inserted slash and terminator).
- Replace `STRCPY`/`STRCAT` with length-limited variants (`StringCchCopyN`/`StringCchCatN`) using the 521-character bound, or allocate the working buffer based on `OutbufLen`.
- Align the RPC IDL range with internal limits (e.g., cap `OutbufLen`/string lengths at `MAX_PATH*2`) and validate at the RPC boundary.
- Share the hardened canonicalization used in the MS08-067 fix across all callers to avoid variant reintroduction.