# MS06-040 (CVE-2006-3439, "Wargbot") Code Location Notes

## Executive Summary

MS06-040 is a critical stack buffer overflow vulnerability in the Windows Server Service that was exploited by multiple bot families including Wargbot and Mocbot in August 2006. The vulnerability exists in the path canonicalization code, specifically in the `CanonicalizePathName` function, where a mismatch between the RPC interface limits (64KB) and internal stack buffer size (~520 bytes) allows remote attackers to achieve code execution.

**Impact**: Unauthenticated remote code execution with SYSTEM privileges on Windows 2000, XP SP0-SP1, and Server 2003 SP0. Windows XP SP2 and Server 2003 SP1 experience denial of service.

**Historical Significance**: This vulnerability, along with MS08-067 (Conficker), represents the class of Server Service path canonicalization bugs that were heavily exploited by worms and botnets. Both vulnerabilities share the same vulnerable code path, with MS08-067 being a variant discovered later.

---

## Educational Overview: Stack Buffer Overflows and RPC Interface Mismatches

*This section explains the vulnerability as if giving a lecture to a high school computer science class.*

### What is a Buffer?

A buffer is like a container of fixed size. Imagine you have a glass that can hold exactly 500ml of water:

```
Stack Memory:
+------------------+
| Return Address   | <-- Where to go after function finishes
+------------------+
| Saved Registers  |
+------------------+
| pathBuffer[521]  | <-- Our "glass" - only holds 521 characters
+------------------+
| Other Variables  |
+------------------+
```

### The Problem: Trusting External Input

The Server Service exposes an RPC function that remote computers can call:

```
Remote Computer                    Your Server
     |                                  |
     | "Please canonicalize this path"  |
     | Path = "AAAA...AAAA" (64KB)      |
     |--------------------------------->|
     |                                  | Tries to put 64KB
     |                                  | into 521-byte buffer
     |                                  | = OVERFLOW!
```

### The "Pouring Water" Analogy

Imagine the RPC interface is like a pipe that can deliver up to 64,000 ml of water, but the internal glass only holds 521 ml:

1. **RPC Interface says**: "I'll accept paths up to 64KB" (the pipe capacity)
2. **Internal code uses**: A 521-byte stack buffer (the glass)
3. **Attacker sends**: 64KB of data through the pipe
4. **Result**: Water overflows the glass, spilling onto the table (stack)

The "table" in this case contains critical data like the return address - where the computer should go after the function finishes. By carefully controlling what "spills," an attacker can redirect execution to their own code.

### Why Doesn't the Code Check the Size?

Actually, it does try to check! Look at line 192:

```c
if (pathLen + prefixLen > MAX_PATH*2 - 1) {
    return ERROR_INVALID_NAME;  // Reject if too long!
}
```

But there's a problem: The checks only validate *before* certain operations. Later processing (like `ConvertPathMacros`) manipulates the string in ways that can bypass these checks.

### The Security Lesson

```
                TRUST BOUNDARY
                     |
    [Untrusted]      |      [Trusted]
                     |
    Attacker's   --> | --> Server's
    Computer         |     Memory
                     |
    RPC allows       |     Stack buffer
    64KB input       |     only 521 bytes
                     |
                     V
              VALIDATION MUST
              HAPPEN HERE!
```

**Key Principle**: Never trust input from the network. Always validate at the trust boundary (where data enters your system), and ensure internal buffers can handle the maximum input size allowed by external interfaces.

### Real-World Impact

When MS06-040 was released on August 8, 2006:
- Exploit code appeared within days
- Wargbot and Mocbot worms spread rapidly
- Organizations scrambled to patch systems
- The vulnerability demonstrated how a single buffer overflow could compromise thousands of servers

---

## Call Path (RPC to Path Canonicalization)

### 1. RPC Interface Definition

**File**: `ds/netapi/svcdlls/srvsvc/idl/srvsvc.idl`
**Lines**: 904-913

```c
NET_API_STATUS
NetprPathCanonicalize(
    [in,string,unique]          SRVSVC_HANDLE   ServerName,
    [in,string]                 LPTSTR          PathName,      // Attacker-controlled
    [out,size_is(OutbufLen)]    LPBYTE          Outbuf,
    [in,range(0, 64000)]        DWORD           OutbufLen,     // Up to 64KB allowed!
    [in,string]                 LPTSTR          Prefix,        // Attacker-controlled
    [in,out]                    LPDWORD         PathType,
    [in]                        DWORD           Flags
);
```

**Critical Issue**: The RPC interface allows `PathName` and `Prefix` to be long strings (up to the RPC max), but internal buffers are much smaller.

### 2. Server-Side RPC Stub

**File**: `ds/netapi/svcdlls/srvsvc/server/canon.c`
**Lines**: 64-109

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
{
    UNREFERENCED_PARAMETER(ServerName);

    return NetpwPathCanonicalize(PathName,    // Passes untrusted input directly
                                    Outbuf,
                                    OutbufLen,
                                    Prefix,
                                    PathType,
                                    Flags
                                    );
}
```

The RPC stub performs no validation and passes attacker-controlled data directly to the vulnerable function.

### 3. Path Canonicalization Wrapper

**File**: `ds/netapi/netlib/pathcan.c`
**Lines**: 57-164

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
    // ... validation of flags and path types ...

    // Calls the vulnerable function at line 159:
    rc = CanonicalizePathName(Prefix, PathName, Outbuf, OutbufLen, NULL);

    // ...
}
```

### 4. Vulnerable Function: CanonicalizePathName

**File**: `ds/netapi/netlib/canon.c`
**Lines**: 85-215

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
    TCHAR   pathBuffer[MAX_PATH*2 + 1];   // Line 166: Only 521 characters!
    DWORD   prefixLen;
    DWORD   pathLen;

    if (ARGUMENT_PRESENT(PathPrefix)) {
        prefixLen = STRLEN(PathPrefix);
        if (prefixLen) {
            // Line 174: Check prefix length
            if (prefixLen > MAX_PATH*2 ) {
                return ERROR_INVALID_NAME;
            }
            STRCPY(pathBuffer, PathPrefix);       // Line 177: Unbounded copy!
            if (!IS_PATH_SEPARATOR(pathBuffer[prefixLen - 1])) {
                STRCAT(pathBuffer, TEXT("\\"));   // Line 179
                ++prefixLen;
            }
            // ...
        }
    }
    // ...

    pathLen = STRLEN(PathName);
    if (pathLen + prefixLen > MAX_PATH*2 - 1) {   // Line 192: Length check
        return ERROR_INVALID_NAME;
    }

    STRCAT(pathBuffer, PathName);                  // Line 196: Concatenation
    ConvertPathCharacters(pathBuffer);

    if (!ConvertDeviceName(pathBuffer)) {
        if (!ConvertPathMacros(pathBuffer)) {      // Line 200: Further processing
            return ERROR_INVALID_NAME;
        }
    }

    // ... copy result to output buffer ...
}
```

### 5. Path Macro Processing

**File**: `ds/netapi/netlib/canon.c`
**Lines**: 416-529

```c
STATIC
BOOL
ConvertPathMacros(
    IN OUT  LPTSTR  Path
)
{
    LPTSTR  ptr = Path;
    LPTSTR  lastSlash = NULL;
    LPTSTR  previousLastSlash = NULL;
    TCHAR   ch;

    // ... handle UNC paths ...

    while ((ch = *ptr) != TCHAR_EOS) {
        if (ch == TCHAR_BACKSLASH) {
            // Track path separators
            previousLastSlash = lastSlash;
            lastSlash = ptr;
        } else if ((ch == TCHAR_DOT) && ((lastSlash == ptr - 1) || (ptr == Path))) {
            TCHAR   nextCh = *(ptr + 1);

            if (nextCh == TCHAR_DOT) {
                // Handle ".." - parent directory reference
                if ((nextCh == TCHAR_BACKSLASH) || (nextCh == TCHAR_EOS)) {
                    if (!previousLastSlash) {
                        return FALSE;
                    }
                    // Line 503: STRCPY on stack buffer - potential overflow!
                    STRCPY(previousLastSlash, ptr + 2);
                    // ...
                }
            } else if (nextCh == TCHAR_BACKSLASH) {
                // Handle "." - current directory reference
                LPTSTR  src = lastSlash ? ptr + 1 : ptr + 2;
                LPTSTR  dst = lastSlash ? lastSlash : ptr;
                // Line 514: Another STRCPY
                STRCPY(dst, src);
                continue;
            }
        }
        ++ptr;
    }
    return TRUE;
}
```

## Vulnerability Mechanism

### The Core Issue

1. **RPC allows large input**: The `NetprPathCanonicalize` RPC accepts path strings limited only by RPC marshaling (effectively very large)

2. **Small stack buffer**: `CanonicalizePathName` uses `TCHAR pathBuffer[MAX_PATH*2 + 1]` (521 wide characters = ~1042 bytes)

3. **Incomplete bounds checking**: While lines 174 and 192 check lengths, they can be bypassed:
   - The checks validate the *initial* concatenation
   - Later processing in `ConvertPathMacros` manipulates the buffer without re-validation
   - Crafted input with path macros (`\..\..`) can cause different overflow conditions

4. **Unsafe string operations**: `STRCPY` and `STRCAT` are used throughout without explicit length limits

### Attack Scenario

```
Attacker sends RPC request:
  PathName = Crafted path with macros
  Prefix   = Long prefix string

Processing:
  1. CanonicalizePathName() allocates 521-char stack buffer
  2. Copies Prefix + PathName (within limits initially)
  3. ConvertPathMacros() processes ".." sequences
  4. String manipulation causes buffer contents to exceed 521 chars
  5. STRCPY writes past buffer boundary
  6. Return address on stack is overwritten
  7. Function returns to attacker-controlled address
  8. Shellcode executes with SYSTEM privileges
```

## Trigger Summary

1. **Connect** to SMB (TCP 445) or NetBIOS (TCP 139)
2. **Bind** to the Server Service RPC endpoint (`\\pipe\\srvsvc`)
3. **Call** `NetprPathCanonicalize` (opnum in srvsvc interface) with:
   - `PathName`: Crafted path containing `\..\` sequences
   - `Prefix`: Long prefix string to assist overflow
   - Carefully calculated lengths to bypass initial checks but overflow during macro processing
4. **Stack buffer overflow** occurs in `CanonicalizePathName`
5. **Code execution** as SYSTEM when function returns

## Relationship to MS08-067

MS06-040 and MS08-067 are closely related:

| Aspect | MS06-040 | MS08-067 |
|--------|----------|----------|
| Date | August 2006 | October 2008 |
| Function | `CanonicalizePathName` | `ConvertPathMacros` (same file) |
| Root cause | Stack buffer + weak checks | State machine error in macro handling |
| Worm | Wargbot, Mocbot | Conficker |
| Same code path | Yes | Yes |
| Same vulnerable file | `ds/netapi/netlib/canon.c` | `ds/netapi/netlib/canon.c` |

Both vulnerabilities exist in the same code path. MS06-040 was the first to be discovered and exploited, while MS08-067 was a subtler variant in the `ConvertPathMacros` logic that survived the MS06-040 patch.

## Fix Considerations

1. **Use safe string functions**: Replace `STRCPY`/`STRCAT` with `StringCchCopy`/`StringCchCat` that take explicit buffer sizes:
   ```c
   // Instead of:
   STRCPY(pathBuffer, PathPrefix);
   // Use:
   StringCchCopy(pathBuffer, ARRAYSIZE(pathBuffer), PathPrefix);
   ```

2. **Validate at RPC boundary**: Add length checks in the RPC stub before calling internal functions:
   ```c
   if (wcslen(PathName) > MAX_PATH || wcslen(Prefix) > MAX_PATH) {
       return ERROR_INVALID_PARAMETER;
   }
   ```

3. **Match interface and implementation limits**: Either:
   - Reduce RPC interface limits to match internal buffer sizes, or
   - Increase internal buffer sizes to match RPC limits (with heap allocation)

4. **Re-validate after processing**: After `ConvertPathMacros`, check that the result still fits in the buffer

5. **Defense in depth**: Enable /GS (stack buffer security check) to detect stack corruption

## References

- Microsoft Security Bulletin MS06-040
- CVE-2006-3439
- [Metasploit Module: ms06_040_netapi](https://www.rapid7.com/db/modules/exploit/windows/smb/ms06_040_netapi/)
- [Exploit-DB: MS06-040](https://www.exploit-db.com/exploits/16367)
- CERT VU#650769

Sources:
- [CVE Details - CVE-2006-3439](https://www.cvedetails.com/cve/CVE-2006-3439/)
- [Rapid7 - MS06-040 Module](https://www.rapid7.com/db/modules/exploit/windows/smb/ms06_040_netapi/)
- [Metasploit Documentation](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/smb/ms06_040_netapi.md)
