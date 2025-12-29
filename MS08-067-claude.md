# MS08-067 Vulnerability Analysis

## Executive Summary

**CVE:** CVE-2008-4250
**Microsoft Bulletin:** MS08-067
**Severity:** Critical (Remote Code Execution)
**CVSS Score:** 10.0
**Affected Service:** Windows Server Service (srvsvc)
**Vulnerable Function:** `NetprPathCanonicalize` / `ConvertPathMacros`
**Attack Vector:** Network (TCP 445/139, no authentication required)
**Famous Exploit:** Conficker Worm (November 2008)

This document analyzes the MS08-067 vulnerability as found in the Windows Server 2003 RTM source code.

---

## Vulnerability Location

| Component | Path |
|-----------|------|
| RPC Entry Point | `ds/netapi/svcdlls/srvsvc/server/canon.c:65` |
| Path Canonicalization Wrapper | `ds/netapi/netlib/pathcan.c:58` |
| Core Canonicalization | `ds/netapi/netlib/canon.c:86` |
| **Vulnerable Function** | `ds/netapi/netlib/canon.c:414` (`ConvertPathMacros`) |

---

## Attack Vector

The vulnerability is exploitable remotely via the Server service RPC interface:

```
┌─────────────────────┐
│   Remote Attacker   │
└──────────┬──────────┘
           │
           ▼ TCP 445 (SMB) or TCP 139 (NetBIOS)
┌──────────────────────────────────────────────────────────┐
│                    Windows Server Service                 │
│                         (srvsvc)                          │
└──────────┬───────────────────────────────────────────────┘
           │ DCE/RPC
           ▼
┌──────────────────────────────────────────────────────────┐
│  NetprPathCanonicalize()                                  │
│  ds/netapi/svcdlls/srvsvc/server/canon.c:65              │
└──────────┬───────────────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────────────────┐
│  NetpwPathCanonicalize()                                  │
│  ds/netapi/netlib/pathcan.c:58                           │
└──────────┬───────────────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────────────────┐
│  CanonicalizePathName()                                   │
│  ds/netapi/netlib/canon.c:86                             │
└──────────┬───────────────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────────────────┐
│  ConvertPathMacros()        ◄── STACK BUFFER OVERFLOW    │
│  ds/netapi/netlib/canon.c:414                            │
└──────────────────────────────────────────────────────────┘
```

---

## Code Analysis

### 1. RPC Entry Point

The Server service exposes `NetprPathCanonicalize` via RPC, which is accessible without authentication:

**File:** `ds/netapi/svcdlls/srvsvc/server/canon.c:64-109`

```c
NET_API_STATUS
NetprPathCanonicalize(
    IN  LPTSTR  ServerName,
    IN  LPTSTR  PathName,
    OUT LPTSTR  Outbuf,
    IN  DWORD   OutbufLen,
    IN  LPTSTR  Prefix,
    OUT LPDWORD PathType,
    IN  DWORD   Flags
    )

/*++
Routine Description:
    Stub function for NetpPathCanonicalize - calls local version

Arguments:
    ServerName  - identifies this server
    PathName    - path name to canonicalize
    Outbuf      - where to place canonicalized path
    OutbufLen   - size of Outbuf
    Prefix      - (historical) prefix for path
    PathType    - type of PathName
    Flags       - controlling flags for NetpPathCanonicalize
--*/

{
    UNREFERENCED_PARAMETER(ServerName);

    return NetpwPathCanonicalize(PathName,
                                    Outbuf,
                                    OutbufLen,
                                    Prefix,
                                    PathType,
                                    Flags
                                    );
}
```

**Security Issue:** No input validation is performed on `PathName` or `Prefix` before passing to the canonicalization function. The attacker-controlled path is passed directly through.

---

### 2. Path Canonicalization Wrapper

**File:** `ds/netapi/netlib/pathcan.c:57-164`

```c
NET_API_STATUS
NetpwPathCanonicalize(
    IN  LPTSTR  PathName,
    IN  LPTSTR  Outbuf,
    IN  DWORD   OutbufLen,
    IN  LPTSTR  Prefix OPTIONAL,
    IN OUT LPDWORD PathType,
    IN  DWORD   Flags
    )
{
    DWORD   rc = 0;
    BOOL    noPrefix = ((Prefix == NULL) || (*Prefix == TCHAR_EOS));
    DWORD   typeOfPrefix;
    DWORD   typeOfPath;

    typeOfPath = *PathType;

    if (Flags & INPCA_FLAGS_RESERVED) {
        return ERROR_INVALID_PARAMETER;
    }

    // Determine type of pathname, if it hasn't been determined yet
    if (!typeOfPath) {
        if (rc = NetpwPathType(PathName, &typeOfPath, 0)) {
            return rc;
        }
    }

    // Validate prefix, if there is one
    if (!noPrefix) {
        if (rc = NetpwPathType(Prefix, &typeOfPrefix, 0)) {
            return rc;
        }
    }

    if (OutbufLen == 0) {
        return NERR_BufTooSmall;
    } else {
        *Outbuf = TCHAR_EOS;
    }

    rc = CanonicalizePathName(Prefix, PathName, Outbuf, OutbufLen, NULL);
    if (rc == NERR_Success) {
        rc = NetpwPathType(Outbuf, PathType, 0);
    }
    return rc;
}
```

**Note:** Basic type validation occurs, but the actual path content is not sanitized before calling `CanonicalizePathName`.

---

### 3. Core Canonicalization Function

**File:** `ds/netapi/netlib/canon.c:85-215`

```c
NET_API_STATUS
CanonicalizePathName(
    IN  LPTSTR  PathPrefix OPTIONAL,
    IN  LPTSTR  PathName,
    OUT LPTSTR  Buffer,
    IN  DWORD   BufferSize,
    OUT LPDWORD RequiredSize OPTIONAL
    )
{
    TCHAR   pathBuffer[MAX_PATH*2 + 1];  // ◄── STACK BUFFER (521 bytes for ANSI)
    DWORD   prefixLen;
    DWORD   pathLen;

    if (ARGUMENT_PRESENT(PathPrefix)) {
        prefixLen = STRLEN(PathPrefix);
        if (prefixLen) {
            // Make sure we don't overrun our buffer
            if (prefixLen > MAX_PATH*2 ) {
                return ERROR_INVALID_NAME;
            }
            STRCPY(pathBuffer, PathPrefix);
            if (!IS_PATH_SEPARATOR(pathBuffer[prefixLen - 1])) {
                STRCAT(pathBuffer, TEXT("\\"));
                ++prefixLen;
            }
            if (IS_PATH_SEPARATOR(*PathName)) {
                ++PathName;
            }
        }
    } else {
        prefixLen = 0;
        pathBuffer[0] = 0;
    }

    pathLen = STRLEN(PathName);
    if (pathLen + prefixLen > MAX_PATH*2 - 1) {
        return ERROR_INVALID_NAME;
    }

    STRCAT(pathBuffer, PathName);
    ConvertPathCharacters(pathBuffer);

    if (!ConvertDeviceName(pathBuffer)) {
        if (!ConvertPathMacros(pathBuffer)) {  // ◄── VULNERABLE CALL
            return ERROR_INVALID_NAME;
        }
    }

    pathLen = STRSIZE(pathBuffer);
    if (pathLen > BufferSize) {
        if (ARGUMENT_PRESENT(RequiredSize)) {
            *RequiredSize = pathLen;
        }
        return NERR_BufTooSmall;
    }

    STRCPY(Buffer, pathBuffer);
    return NERR_Success;
}
```

**Key Points:**
- `pathBuffer` is a **stack-allocated buffer** of `MAX_PATH*2 + 1` bytes (521 bytes for ANSI, 1042 bytes for Unicode)
- Length checks exist but are insufficient to prevent the overflow in `ConvertPathMacros`
- The concatenated path is passed to `ConvertPathMacros` for `..` resolution

---

### 4. The Vulnerable Function

**File:** `ds/netapi/netlib/canon.c:414-529`

```c
STATIC
BOOL
ConvertPathMacros(
    IN OUT  LPTSTR  Path
    )

/*++
Routine Description:
    Removes path macros (\.. and \.) and replaces them with the correct level
    of path components. This routine expects path macros to appear in a path
    like this:

        <path>\.
        <path>\.\<more-path>
        <path>\..
        <path>\..\<more-path>

    I.e. a macro will either be terminated by the End-Of-String character (\0)
    or another path separator (\).
--*/

{
    LPTSTR  ptr = Path;
    LPTSTR  lastSlash = NULL;
    LPTSTR  previousLastSlash = NULL;
    TCHAR   ch;

    //
    // if this path is UNC then move the pointer past the computer name to the
    // start of the (supposed) share name. Treat the remnants as a relative path
    //
    if (IS_PATH_SEPARATOR(Path[0]) && IS_PATH_SEPARATOR(Path[1])) {
        Path += 2;
        while (!IS_PATH_SEPARATOR(*Path) && *Path) {
            ++Path;
        }
        if (!*Path) {
            return FALSE;   // we had \\computername which is bad
        }
        ++Path; // past \ into share name
        if (IS_PATH_SEPARATOR(*Path)) {
            return FALSE;   // we had \\computername\\ which is bad
        }
    }

    ptr = Path;

    //
    // remove all \., .\, \.. and ..\ from path
    //
    while ((ch = *ptr) != TCHAR_EOS) {
        if (ch == TCHAR_BACKSLASH) {
            if (lastSlash == ptr - 1) {
                return FALSE;
            }
            previousLastSlash = lastSlash;
            lastSlash = ptr;
        } else if ((ch == TCHAR_DOT) && ((lastSlash == ptr - 1) || (ptr == Path))) {
            TCHAR   nextCh = *(ptr + 1);

            if (nextCh == TCHAR_DOT) {
                TCHAR   nextCh = *(ptr + 2);

                // ════════════════════════════════════════════════════════════
                // VULNERABLE CODE BLOCK - Lines 499-509
                // ════════════════════════════════════════════════════════════
                if ((nextCh == TCHAR_BACKSLASH) || (nextCh == TCHAR_EOS)) {
                    if (!previousLastSlash) {
                        return FALSE;
                    }
                    STRCPY(previousLastSlash, ptr + 2);   // ◄── OVERFLOW HERE
                    if (nextCh == TCHAR_EOS) {
                        break;
                    }
                    ptr = lastSlash = previousLastSlash;
                    previousLastSlash = BackUpPath(Path, ptr - 1);
                }
                // ════════════════════════════════════════════════════════════

            } else if (nextCh == TCHAR_BACKSLASH) {
                LPTSTR  src = lastSlash ? ptr + 1 : ptr + 2;
                LPTSTR  dst = lastSlash ? lastSlash : ptr;

                STRCPY(dst, src);
                continue;   // at current character position
            } else if (nextCh == TCHAR_EOS) {
                *(lastSlash ? lastSlash : ptr) = TCHAR_EOS;
                break;
            }
        }
        ++ptr;
    }

    return TRUE;
}
```

---

## The Vulnerability Explained

### Root Cause

The vulnerability is a **stack buffer overflow** caused by improper pointer arithmetic when processing `..` (parent directory) path components.

### The Flaw in Detail

1. **Pointer Tracking:** The function maintains two pointers:
   - `lastSlash`: Points to the most recent `\` encountered
   - `previousLastSlash`: Points to the `\` before `lastSlash`

2. **The Problematic Code Path:**
   ```c
   if (nextCh == TCHAR_DOT) {
       TCHAR   nextCh = *(ptr + 2);

       if ((nextCh == TCHAR_BACKSLASH) || (nextCh == TCHAR_EOS)) {
           if (!previousLastSlash) {
               return FALSE;
           }
           STRCPY(previousLastSlash, ptr + 2);   // ◄── THE BUG
           // ...
           previousLastSlash = BackUpPath(Path, ptr - 1);
       }
   }
   ```

3. **The Bug:** When processing a sequence like `\..\..\`, the function:
   - Copies the remainder of the path to `previousLastSlash`
   - Updates `previousLastSlash` via `BackUpPath()`
   - **However**, with carefully crafted input, `previousLastSlash` can point to memory **before** the start of the stack buffer

4. **Missing Bounds Check:** There is no validation that `previousLastSlash` remains within the bounds of `pathBuffer` after the `BackUpPath()` call.

### The BackUpPath Function

**File:** `ds/netapi/netlib/canon.c:531-560`

```c
STATIC
LPTSTR
BackUpPath(
    IN  LPTSTR  Stopper,
    IN  LPTSTR  Path
    )

/*++
Routine Description:
    Searches backwards in a string for a path separator character (back-slash)

Arguments:
    Stopper - pointer past which Path cannot be backed up
    Path    - pointer to path to back up

Return Value:
    Pointer to backed-up path, or NULL if an error occurred
--*/

{
    while ((*Path != TCHAR_BACKSLASH) && (Path != Stopper)) {
        --Path;
    }
    return (*Path == TCHAR_BACKSLASH) ? Path : NULL;
}
```

**Issue:** While `BackUpPath` has a `Stopper` parameter, the way it's called doesn't prevent `previousLastSlash` from ending up at an invalid location due to the complex interaction of multiple `..` sequences.

---

## Exploitation

### Attack Requirements

- **Network Access:** TCP port 445 (SMB) or 139 (NetBIOS)
- **Authentication:** None required
- **User Interaction:** None required

### Exploit Payload Structure

A typical exploit sends a malicious path through the `NetprPathCanonicalize` RPC call:

```
\\server\share\AAAA\..\..\..\..\..\<shellcode>
```

The crafted path causes:
1. Multiple `..` sequences to be processed
2. `previousLastSlash` to point before the buffer
3. `STRCPY` to write attacker-controlled data to the stack
4. Return address overwrite
5. Shellcode execution

### Memory Layout During Overflow

```
Stack (high addresses at top):
┌─────────────────────────────────────┐
│         Return Address              │ ◄── Overwritten with shellcode addr
├─────────────────────────────────────┤
│         Saved EBP                   │ ◄── Overwritten
├─────────────────────────────────────┤
│         Local Variables             │ ◄── Overwritten
├─────────────────────────────────────┤
│                                     │
│    pathBuffer[MAX_PATH*2 + 1]       │ ◄── Start of buffer
│                                     │
├─────────────────────────────────────┤
│                                     │
│    previousLastSlash points here    │ ◄── STRCPY destination (BEFORE buffer!)
│         (underflow)                 │
└─────────────────────────────────────┘
```

---

## The Conficker Worm

MS08-067 gained notoriety as the vulnerability exploited by the **Conficker worm** (also known as Downadup or Kido), which began spreading in November 2008.

### Conficker Impact

- **Infections:** Estimated 9-15 million computers worldwide
- **Targets:** Windows 2000, XP, Vista, Server 2003, Server 2008
- **Spread:** Exploited MS08-067, USB drives, and network shares
- **Payload:** Created botnet, disabled security software, blocked Windows Update

### Timeline

| Date | Event |
|------|-------|
| October 23, 2008 | Microsoft releases MS08-067 patch |
| November 21, 2008 | Conficker.A discovered in the wild |
| December 29, 2008 | Conficker.B adds USB propagation |
| February 2009 | Conficker.C adds P2P communication |
| April 1, 2009 | Conficker.E activates (anticipated "payload day") |

### Why It Was So Effective

1. **Pre-auth RCE:** No credentials needed
2. **Wormable:** Self-propagating across networks
3. **Wide Attack Surface:** Server service enabled by default
4. **Slow Patching:** Many systems remained unpatched for months

---

## Remediation

### Microsoft's Fix

The patch adds proper bounds checking to ensure `previousLastSlash` never points outside the valid buffer region. The fix validates:

1. That the path doesn't contain more `..` components than valid directories
2. That pointer arithmetic stays within buffer bounds
3. That `STRCPY` destinations are always valid

### Mitigations

1. **Apply MS08-067 patch**
2. **Block TCP 445/139** at network perimeter
3. **Disable Server service** if not needed
4. **Network segmentation** to limit lateral movement
5. **Enable Windows Firewall**

---

## References

- [Microsoft Security Bulletin MS08-067](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067)
- [CVE-2008-4250](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250)
- [Conficker Working Group](https://www.confickerworkinggroup.org/)
- [SANS Analysis of Conficker](https://www.sans.org/blog/conficker-analysis/)

---

## Source Code References

| File | Line | Function | Description |
|------|------|----------|-------------|
| `ds/netapi/svcdlls/srvsvc/server/canon.c` | 65 | `NetprPathCanonicalize` | RPC entry point |
| `ds/netapi/netlib/pathcan.c` | 58 | `NetpwPathCanonicalize` | Wrapper function |
| `ds/netapi/netlib/canon.c` | 86 | `CanonicalizePathName` | Stack buffer allocation |
| `ds/netapi/netlib/canon.c` | 166 | - | `pathBuffer[MAX_PATH*2 + 1]` declaration |
| `ds/netapi/netlib/canon.c` | 414 | `ConvertPathMacros` | **Vulnerable function** |
| `ds/netapi/netlib/canon.c` | 503 | - | **Vulnerable STRCPY** |
| `ds/netapi/netlib/canon.c` | 531 | `BackUpPath` | Pointer backup helper |
