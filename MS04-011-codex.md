# MS04-011 (CVE-2003-0533, “LSASS/Sasser”) Code Location Notes

## Overview
The MS04-011 LSASS vulnerability exploited by Sasser is a stack overflow in `lsasrv.dll`’s DsRole logging path. A remote caller invokes the DsRole upgrade RPC over `lsarpc` and provides an oversized string; the server logs those parameters with an unbounded `wvsprintfW` into a 1024-WCHAR stack buffer, corrupting the stack of the SYSTEM‑privileged LSASS process.

## Call Path (lsarpc → DsRole → Logging)
1. **RPC contract**: `ds/security/dsrole/idl/dssetup.idl` exposes `DsRolerUpgradeDownlevelServer` (UUID `3919286a-b10c-11d0-9ba8-00c04fd92ef5`) over `\\pipe\\lsarpc`, with many `[string]` parameters (e.g., `lpDnsDomainName`, `lpSystemVolumeRootPath`, database/log paths). No size bounds are enforced in the IDL.

2. **Server entry**: `ds/security/dsrole/server/dispatch.c:2088-2138` (`DsRolerUpgradeDownlevelServer`) logs each attacker-controlled parameter:
   ```c
   DsRolepInitializeLog();
   DsRolepLogPrint((DEB_TRACE, "DsRolerDcAsDc: DnsDomainName  %ws\n", DnsDomainName));
   DsRolepLogPrint((DEB_TRACE, "\tSystemVolumeRootPath  %ws\n", SystemVolumeRootPath));
   // ...other user-controlled strings...
   ```

3. **Vulnerable logging**: `ds/security/dsrole/server/log.c:353-429` `DsRolepDebugDumpRoutine` formats into a fixed 1024-WCHAR stack buffer with no length check:
   ```c
   #define DsRolepDebugDumpRoutine_BUFFERSIZE 1024
   WCHAR OutputBuffer[DsRolepDebugDumpRoutine_BUFFERSIZE];
   ...
   length += (ULONG) wvsprintfW(&OutputBuffer[length], Format, arglist); // unbounded
   ASSERT(length <= sizeof(OutputBuffer)/sizeof(WCHAR)); // debug only
   ```
   An oversized string parameter overflows `OutputBuffer`, overwriting saved return state.

## Trigger Summary
Bind to `lsarpc` (named pipe) and call `DsRolerUpgradeDownlevelServer` (opnum 0x09) with a very long Unicode string in the first few parameters (e.g., `lpDnsDomainName` or system volume path). During parameter logging, `wvsprintfW` writes past the 1024-WCHAR stack buffer in `DsRolepDebugDumpRoutine`, yielding pre-auth remote code execution as SYSTEM. This is the vector implemented in Metasploit `exploit/windows/smb/ms04_011_lsass`.

## Fix Considerations
- Enforce size limits on all `[string]` parameters at the RPC boundary; reject or truncate inputs well below the 1024-WCHAR log buffer.
- Replace `wvsprintfW` with bounded formatting (`StringCchVPrintfW`/`_vsnwprintf_s`) using remaining buffer length.
- Avoid logging attacker-controlled data into fixed stack buffers; move to heap with explicit length checks or disable verbose logging for remote inputs.
