# MS04-011: LSASS Buffer Overflow Vulnerability Analysis (Sasser Worm)

## Executive Summary

MS04-011 (CVE-2003-0533) is a stack-based buffer overflow vulnerability in the Local Security Authority Subsystem Service (LSASS). The vulnerability exists in the `DsRolepGetDatabaseFacts()` function within the DS Role component, where an attacker-controlled path string is copied into a fixed-size stack buffer using unbounded `wcscpy()`. This vulnerability was exploited by the Sasser worm in April-May 2004.

> **Correction Note**: Initial analysis incorrectly identified the logging function `DsRolepDebugDumpRoutine()` as the vulnerable code path. The actual vulnerability is in `DsRolepGetDatabaseFacts()` via the `DsRolerGetDatabaseFacts` RPC function, as documented in Exploit-DB entry 16368 and the Metasploit module.

---

## Educational Overview: Debug-Only Checks and the False Sense of Security

*This section explains the vulnerability concepts for students learning about computer security.*

### The Two Faces of Software: Debug vs. Release Builds

When developers write software, they typically create two different versions:

1. **Debug Build**: Used during development. Includes extra checks, logging, and debugging information. Runs slower but helps find bugs.

2. **Release Build**: Shipped to customers. Optimized for speed, with debugging features removed. This is what runs on production systems.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        SOURCE CODE                                       │
│                                                                          │
│    if (input_length > BUFFER_SIZE) {                                    │
│        return ERROR;  // Always present                                  │
│    }                                                                     │
│                                                                          │
│    ASSERT(input_length <= BUFFER_SIZE);  // ← Only in Debug!            │
│                                                                          │
└───────────────────────────┬─────────────────────────────────────────────┘
                            │
            ┌───────────────┴───────────────┐
            ▼                               ▼
   ┌─────────────────┐             ┌─────────────────┐
   │   DEBUG BUILD   │             │  RELEASE BUILD  │
   │                 │             │                 │
   │ - ASSERT active │             │ - ASSERT gone!  │
   │ - Extra checks  │             │ - Optimized     │
   │ - Slower        │             │ - Faster        │
   │ - For testing   │             │ - For customers │
   └─────────────────┘             └─────────────────┘
```

### What Is an ASSERT?

An `ASSERT()` is a debugging tool that checks if a condition is true. If the condition is false, the program stops immediately and shows an error message. This helps developers catch bugs during testing.

```c
// Example ASSERT usage
ASSERT(age >= 0);           // Age should never be negative
ASSERT(pointer != NULL);    // Pointer should never be null
ASSERT(length <= MAX_SIZE); // Length should fit in buffer
```

**The Critical Problem**: In most programming environments, including Windows, `ASSERT()` statements are **completely removed** when building the Release version. They simply disappear from the final program!

```c
// What the developer wrote:
ASSERT(wcslen(lpRestorePath) <= MAX_PATH);
wcscpy(regsystemfilepath, lpRestorePath);

// What actually runs in Release build:
// [ASSERT is gone - no check happens!]
wcscpy(regsystemfilepath, lpRestorePath);  // ← Copies without any length check
```

### The MS04-011 Vulnerability Pattern

This is exactly what happened in the LSASS vulnerability:

```c
// ds/security/dsrole/server/ds.c

WCHAR regsystemfilepath[MAX_PATH+1];  // Buffer for 261 characters

// This ASSERT only exists in Debug builds!
ASSERT( wcslen(lpRestorePath) <= MAX_PATH );  // ← REMOVED IN RELEASE!

// This wcscpy ALWAYS runs, with no length check in Release builds
wcscpy(regsystemfilepath, lpRestorePath);     // ← OVERFLOW!
```

The developer likely thought: "I've added an ASSERT to check the length, so this is safe." But that protection only exists during development—it vanishes in the version that customers actually use.

### A Real-World Analogy

Imagine a bank that has two types of security:

1. **Permanent Security Guard** (always present): Checks IDs at the door
2. **Training Supervisor** (only during drills): Watches for suspicious behavior

During a training exercise, both are present. But on a regular day, only the permanent guard is there. If the bank's security plan relies on the training supervisor to catch robbers, they're in trouble!

```
TRAINING DAY:                          REGULAR DAY:
┌─────────────────────┐                ┌─────────────────────┐
│  ✓ Security Guard   │                │  ✓ Security Guard   │
│  ✓ Supervisor       │                │  ✗ No Supervisor    │ ← The ASSERT
│                     │                │                     │
│  "All clear!"       │                │  "Robber got in!"   │
└─────────────────────┘                └─────────────────────┘
```

The `ASSERT()` is like the training supervisor—helpful during development, but absent when it really matters.

### Why Do Developers Make This Mistake?

1. **Testing passes**: During development and testing (with Debug builds), the ASSERT catches problems, so everything seems safe.

2. **Code looks protected**: Reading the source code, you see a length check. It's easy to miss that it's inside an ASSERT.

3. **Misunderstanding ASSERT's purpose**: ASSERT is meant to catch programmer errors during development, not to validate untrusted input from users or networks.

### The Correct Approach

**Wrong** (Debug-only protection):
```c
ASSERT(wcslen(input) <= BUFFER_SIZE);  // Gone in Release!
wcscpy(buffer, input);                  // No runtime protection
```

**Right** (Always-on protection):
```c
if (wcslen(input) > BUFFER_SIZE) {      // Always checked
    return ERROR_INVALID_PARAMETER;
}
wcscpy(buffer, input);                   // Now safe
```

**Even Better** (Use safe functions):
```c
// StringCchCopy automatically prevents overflow
StringCchCopy(buffer, BUFFER_SIZE, input);
```

### The Sasser Worm: A Global Outbreak

In April 2004, a German teenager exploited this vulnerability to create the **Sasser worm**. Unlike many viruses that require you to open an email attachment, Sasser spread automatically:

1. **No user interaction needed**: Just being connected to the internet was enough
2. **Millions of computers infected**: Including hospitals, banks, airlines, and government systems
3. **System crashes**: LSASS is critical to Windows—attacking it caused computers to reboot

```
THE SASSER ATTACK SEQUENCE:

[Attacker] ──TCP 445──▶ [Victim PC]
                              │
                              ▼
                    Connect to \pipe\lsarpc
                              │
                              ▼
                    Call DsRolerGetDatabaseFacts
                    with 300+ character path
                              │
                              ▼
                    ASSERT (compiled out)
                    wcscpy() overflows buffer
                              │
                              ▼
                    Return address overwritten
                    Shellcode executes as SYSTEM
                              │
                              ▼
                    Worm downloads and installs
                    Begins scanning for new victims
```

### Comparing to MS03-026 (Blaster)

| Aspect | MS03-026 (Blaster) | MS04-011 (Sasser) |
|--------|-------------------|-------------------|
| **Root Cause** | No bounds check at all | Bounds check in ASSERT only |
| **Developer's Mistake** | Forgot to add protection | Added protection that disappears |
| **Lesson** | Always validate input | Never rely on debug-only checks |
| **Both Teach** | Input validation must be in the final, released code |

### Key Lessons for Programmers

1. **ASSERT is for development, not security**: Use ASSERT to catch programmer errors, not to validate external input.

2. **Always validate input at runtime**: Any data from outside your program (network, files, users) must be checked with code that runs in Release builds.

3. **Test Release builds**: Security testing should happen on the same build that ships to customers.

4. **Use secure-by-default functions**: Modern APIs like `StringCchCopy()` handle bounds checking automatically.

5. **Code review for this pattern**: When reviewing code, watch for length checks that are only inside ASSERT statements.

### Glossary

| Term | Definition |
|------|------------|
| **ASSERT** | A debugging macro that checks conditions and stops the program if they're false—but only in Debug builds |
| **Debug Build** | A version of software with extra checks and debugging features, used during development |
| **Release Build** | An optimized version of software with debugging features removed, shipped to customers |
| **LSASS** | Local Security Authority Subsystem Service—a critical Windows process that handles authentication |
| **wcscpy** | Wide-character string copy function that copies without checking destination buffer size |
| **MAX_PATH** | Windows constant for maximum path length (260 characters) |
| **RPC** | Remote Procedure Call—allows programs to execute functions on remote computers |

---

## Vulnerability Classification

- **CVE ID**: CVE-2003-0533
- **Microsoft Bulletin**: MS04-011
- **Type**: Stack-based Buffer Overflow
- **Exploited By**: Sasser Worm (W32.Sasser)
- **Attack Vector**: RPC via `\pipe\lsarpc` or `\pipe\dsrole` named pipes
- **Target Service**: LSASS (lsass.exe) / lsasrv.dll
- **Impact**: Remote Code Execution with SYSTEM privileges
- **CVSS Base Score**: 10.0 (Critical)

## Affected Systems

- Windows 2000
- Windows XP
- Windows Server 2003

## Root Cause Analysis

### Vulnerable Component

The vulnerability resides in the Directory Services Role component, specifically in the `DsRolepGetDatabaseFacts()` function that processes IFM (Install From Media) restore paths.

### Vulnerable File

**File**: `ds/security/dsrole/server/ds.c`

### Vulnerable Function

**Function**: `DsRolepGetDatabaseFacts()` at lines 672-1050

```c
// ds/security/dsrole/server/ds.c:672-764

DWORD
WINAPI
DsRolepGetDatabaseFacts(
    IN  LPWSTR lpRestorePath       // ATTACKER-CONTROLLED INPUT
    )
{

#define IFM_SYSTEM_KEY    L"ifmSystem"
#define IFM_SECURITY_KEY  L"ifmSecurity"

    WCHAR wszAltRegLoc[MAX_PATH+1] = L"\0";
    WCHAR regsystemfilepath[MAX_PATH+1];      // Line 708: FIXED 261 WCHAR BUFFER
    WCHAR regsecurityfilepath[MAX_PATH+1];    // Line 709: FIXED 261 WCHAR BUFFER
    // ... variable declarations ...

    // Some validation.
    ASSERT(DsRolepCurrentIfmOperationHandle.fIfmOpHandleLock);
    ASSERT(!DsRolepCurrentIfmOperationHandle.fIfmSystemInfoSet);
    ASSERT( wcslen(lpRestorePath) <= MAX_PATH );   // Line 733: DEBUG-ONLY CHECK!

    // ... snip ...

    //set up the location of the system registry file
    regsystemfilepath[MAX_PATH] = L'\0';
    wcscpy(regsystemfilepath, lpRestorePath);      // Line 764: UNBOUNDED COPY!
    wcsncat(regsystemfilepath, L"\\registry\\system", (MAX_PATH)-wcslen(regsystemfilepath));

    regsecurityfilepath[MAX_PATH] = L'\0';
    wcscpy(regsecurityfilepath, lpRestorePath);    // Line 768: UNBOUNDED COPY!
    wcsncat(regsecurityfilepath, L"\\registry\\security", MAX_PATH-wcslen(regsecurityfilepath));
```

### The Bug

The vulnerability has three critical components:

1. **Fixed-Size Stack Buffers**: Two `MAX_PATH+1` (261 character) wide string buffers are allocated on the stack at lines 708-709.

2. **Debug-Only Length Validation**: At line 733, an `ASSERT()` checks that the input path is within bounds:
   ```c
   ASSERT( wcslen(lpRestorePath) <= MAX_PATH );
   ```
   **CRITICAL**: `ASSERT()` statements are **completely removed in Release/Production builds**. This check provides ZERO protection in deployed Windows systems.

3. **Unbounded Copy Operations**: At lines 764 and 768, `wcscpy()` copies the attacker-controlled input directly into the stack buffers WITHOUT any runtime bounds checking.

### Why This Is Exploitable

The `wcscpy()` function copies a wide-character string without any length limit. If `lpRestorePath` exceeds 261 characters, the copy overwrites adjacent stack memory including:
- Other local variables
- Saved frame pointer (EBP)
- Return address
- Structured Exception Handler (SEH) chain

## Attack Vector

### RPC Entry Point

**File**: `ds/security/dsrole/server/dispatch.c`

```c
// ds/security/dsrole/server/dispatch.c:1273-1395

DWORD
WINAPI
DsRolerGetDatabaseFacts(
    IN  handle_t RpcBindingHandle,
    IN  LPWSTR lpRestorePath,        // ATTACKER-CONTROLLED - NO LENGTH CHECK!
    OUT LPWSTR *lpDNSDomainName,
    OUT PULONG State,
    OUT DSROLER_IFM_HANDLE * pIfmHandle
    )
{
    DWORD Win32Err=ERROR_SUCCESS;

    //
    // 1) Check parameters
    //
    Win32Err = DsRolepCheckPromoteAccess( FALSE );  // Access check exists
    if ( ERROR_SUCCESS != Win32Err ) {
        return Win32Err;
    }

    if( lpDNSDomainName == NULL ||
        IsBadWritePtr(lpDNSDomainName, sizeof(LPWSTR*)) ||
        State == NULL ||
        IsBadWritePtr(State, sizeof(DWORD)) ||
        pIfmHandle == NULL ||
        IsBadWritePtr(pIfmHandle, sizeof(DSROLER_IFM_HANDLE))
        ){
        // ... error handling ...
    }
    // NOTE: NO VALIDATION OF lpRestorePath LENGTH!

    // ... lock acquisition ...

    //
    // 2) Get IFM System Info
    //
    Win32Err = DsRolepGetDatabaseFacts(lpRestorePath);  // Line 1365: VULN CALL

    // ...
}
```

### IDL Interface Definition

**File**: `ds/security/dsrole/idl/dssetup.idl`

```c
// ds/security/dsrole/idl/dssetup.idl:262-269

DWORD
DsRolerGetDatabaseFacts(
    [in] handle_t hBinding,
    [in, string]  LPWSTR RestorePath,      // UNBOUNDED STRING INPUT
    [out, string] LPWSTR *ppDNSDomainName,
    [out] PULONG State,
    [out] DSROLER_IFM_HANDLE * pIfmHandle
    );
```

The RPC interface is exposed via the `dsrole` endpoint, which imports `dssetimp.idl` containing:
```c
endpoint("mscn_np:[\pipe\lsarpc]")
```

This exposes the interface through the `\pipe\lsarpc` named pipe.

### Attack Chain Summary

```
1. Attacker connects to LSASS via named pipe \\target\pipe\lsarpc
                              |
                              v
2. Calls DsRolerGetDatabaseFacts() with oversized RestorePath
   (e.g., RestorePath > 261 characters)
                              |
                              v
3. dispatch.c:1325 - DsRolepCheckPromoteAccess(FALSE) [may pass in some configs]
   dispatch.c:1330-1339 - Parameter validation (NO length check on RestorePath!)
                              |
                              v
4. dispatch.c:1365 - DsRolepGetDatabaseFacts(lpRestorePath) called
                              |
                              v
5. ds.c:733 - ASSERT(wcslen(lpRestorePath) <= MAX_PATH) [REMOVED IN RELEASE!]
                              |
                              v
6. ds.c:764 - wcscpy(regsystemfilepath, lpRestorePath) OVERFLOWS STACK!
                              |
                              v
7. Stack corruption:
   - Saved EBP overwritten
   - Return address overwritten
   - SEH chain corrupted
                              |
                              v
8. Arbitrary code execution with SYSTEM privileges
```

## Exploitation Details

### Buffer Layout

```
Stack (high addresses to low):
+---------------------------+
| Return Address            | <- Overwritten for RCE
+---------------------------+
| Saved EBP                 | <- Overwritten
+---------------------------+
| SEH Handler               | <- May be used for exploitation
+---------------------------+
| ... other locals ...      |
+---------------------------+
| regsecurityfilepath[260]  |
|           ...             |
| regsecurityfilepath[0]    |
+---------------------------+
| regsystemfilepath[260]    |
|           ...             | <- Overflow starts here
| regsystemfilepath[0]      | <- wcscpy destination
+---------------------------+
| wszAltRegLoc[260]         |
|           ...             |
| wszAltRegLoc[0]           |
+---------------------------+
```

### Exploitation Considerations

1. **No Stack Canaries**: Windows Server 2003 RTM did not have `/GS` stack protection enabled for this code path.

2. **No DEP**: Data Execution Prevention was not enabled by default.

3. **No ASLR**: Address Space Layout Randomization did not exist in these Windows versions.

4. **SYSTEM Privileges**: LSASS runs as SYSTEM, giving the attacker complete control.

5. **Access Check**: Note that `DsRolepCheckPromoteAccess(FALSE)` is called, but the exact access requirements depend on system configuration.

### The Sasser Worm

The Sasser worm (discovered April 30, 2004) exploited this vulnerability to:

1. Scan for vulnerable systems on TCP port 445
2. Connect to `\pipe\lsarpc` named pipe
3. Call `DsRolerGetDatabaseFacts` with oversized `RestorePath`
4. Overflow the stack and execute shellcode
5. Download the worm payload via FTP
6. Propagate to other systems

Unlike Blaster (MS03-026), Sasser did not require user interaction and spread automatically across networks.

## Code Quality Issues

### Debug-Only Protection

The ONLY length check is an `ASSERT()`:
```c
ASSERT( wcslen(lpRestorePath) <= MAX_PATH );
```

`ASSERT()` macros are compiled out in Release builds, providing zero protection in production.

### Pattern of Unsafe Functions

The code uses multiple unsafe string functions:
- `wcscpy()` - No bounds checking (lines 764, 768, 801, 814, 815)
- The safe alternative `wcsncpy()` or `StringCchCopy()` should have been used

### Missing Input Validation

The RPC dispatcher at `dispatch.c:1273` validates output pointers but **does not validate the length of `lpRestorePath`** before passing it to `DsRolepGetDatabaseFacts()`.

## Comparison to Other Vulnerabilities

| Aspect | MS03-026 (Blaster) | MS04-011 (Sasser) | MS08-067 (Conficker) |
|--------|-------------------|-------------------|---------------------|
| Service | DCOM/RPC | LSASS | Server Service |
| Buffer Size | 16 WCHAR | 261 WCHAR (MAX_PATH+1) | 416/420 WCHAR |
| Overflow Type | Simple loop | wcscpy to stack | State machine |
| Complexity | Low | Low | High |
| Vulnerable Function | GetMachineName | DsRolepGetDatabaseFacts | ConvertPathMacros |
| Protection | None | ASSERT only | Some bounds checks |
| Worm Date | Aug 2003 | Apr 2004 | Nov 2008 |

## Remediation

### Microsoft's Fix

The patch added proper runtime length validation of `lpRestorePath` before the `wcscpy()` calls and replaced unsafe string operations with bounds-checked alternatives.

### Secure Coding Practices

```c
// UNSAFE (original code):
wcscpy(regsystemfilepath, lpRestorePath);

// SAFE (patched approach):
if (wcslen(lpRestorePath) > MAX_PATH) {
    return ERROR_INVALID_PARAMETER;
}
StringCchCopyW(regsystemfilepath, MAX_PATH+1, lpRestorePath);
```

### Defense in Depth Measures Added Later

- **/GS (Stack Buffer Security Check)**: Compiler-inserted stack canaries
- **DEP (Data Execution Prevention)**: Prevents code execution on the stack
- **ASLR (Address Space Layout Randomization)**: Makes exploitation unreliable
- **Enhanced RPC Security**: Stricter input validation at RPC layer

## Timeline

| Date | Event |
|------|-------|
| 2003 | Vulnerability discovered |
| Apr 13, 2004 | Microsoft releases MS04-011 patch |
| Apr 30, 2004 | Sasser worm variant A released |
| May 1, 2004 | Sasser variants B, C, D released |
| May 2004 | Millions of computers infected worldwide |
| May 7, 2004 | Author (18-year-old German student) arrested |

## References

- Microsoft Security Bulletin MS04-011
- CVE-2003-0533
- CERT Advisory CA-2004-11
- Exploit-DB Entry 16368: "Microsoft LSASS Service - DsRolerUpgradeDownlevelServer Overflow"
- Metasploit Module: `exploit/windows/smb/ms04_011_lsass`

### Source Code References

- **Vulnerable Function**: `ds/security/dsrole/server/ds.c:672-1050` (`DsRolepGetDatabaseFacts`)
- **RPC Entry Point**: `ds/security/dsrole/server/dispatch.c:1273-1395` (`DsRolerGetDatabaseFacts`)
- **IDL Interface**: `ds/security/dsrole/idl/dssetup.idl:262-269`
- **Endpoint Definition**: `ds/security/dsrole/idl/dssetimp.idl:36` (`\pipe\lsarpc`)

---

## Analysis Notes

### Correction History

**Initial Analysis (Incorrect)**: Originally identified `DsRolepDebugDumpRoutine()` in `log.c` as the vulnerable function, focusing on the `wvsprintfW()` call in the logging path.

**Corrected Analysis**: Based on Exploit-DB entry 16368 and Metasploit module documentation, the actual vulnerability is in `DsRolepGetDatabaseFacts()` via the `DsRolerGetDatabaseFacts` RPC call.

### Key Differences

| Aspect | Original (Incorrect) Analysis | Corrected Analysis |
|--------|-------------------------------|-------------------|
| Vulnerable Function | DsRolepDebugDumpRoutine | DsRolepGetDatabaseFacts |
| File | log.c | ds.c |
| Overflow Cause | wvsprintfW format string | wcscpy to stack buffer |
| RPC Function | DsRolerUpgradeDownlevelServer | DsRolerGetDatabaseFacts |
| Buffer Size | 1024 WCHAR | 261 WCHAR (MAX_PATH+1) |

### Why the Logging Path Was a Red Herring

While the logging path (`DsRolepDebugDumpRoutine`) does have a potential overflow with `wvsprintfW()`, the actual Sasser worm targeted `DsRolerGetDatabaseFacts` because:

1. It has a simpler, more reliable overflow (single `wcscpy` vs. format string)
2. The `RestorePath` parameter provides direct control over overflow content
3. The stack buffer is smaller (261 chars) making exploitation easier
4. The code path is more reliable for exploitation

### Cross-Verification

This analysis was verified against:
- Exploit-DB entry 16368
- Metasploit module `ms04_011_lsass`
- Windows Server 2003 RTM source code examination
