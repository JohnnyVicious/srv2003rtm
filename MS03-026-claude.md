# MS03-026 Vulnerability Analysis (Blaster Worm)

## Executive Summary

**CVE:** CVE-2003-0352
**Microsoft Bulletin:** MS03-026
**Severity:** Critical (Remote Code Execution)
**CVSS Score:** 10.0
**Affected Service:** DCOM RPC Interface (RPCSS/DCOMSS)
**Vulnerable Function:** `GetMachineName()`
**Attack Vector:** Network (TCP 135, no authentication required)
**Famous Exploit:** Blaster Worm (MSBlast, Lovesan) - August 2003

This document analyzes the MS03-026 vulnerability as found in the Windows Server 2003 RTM source code.

---

## Educational Overview: Understanding Buffer Overflows

*This section explains the vulnerability concepts for students learning about computer security.*

### What Is a Buffer?

Imagine you have a row of 16 mailboxes at an apartment building, numbered 0 through 15. Each mailbox can hold exactly one letter. This row of mailboxes is like a **buffer** in computer memory—a fixed-size container that holds data.

```
Buffer (16 slots):
┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
│ 0 │ 1 │ 2 │ 3 │ 4 │ 5 │ 6 │ 7 │ 8 │ 9 │10 │11 │12 │13 │14 │15 │
└───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
```

In this vulnerability, the buffer is designed to hold a **computer name**, which Windows limits to 15 characters plus a null terminator (a special "end of string" marker), totaling 16 slots.

### What Is a Buffer Overflow?

A buffer overflow happens when you try to put more data into a buffer than it can hold. Using our mailbox analogy: what if someone tried to deliver 50 letters to our 16 mailboxes?

```
Trying to store "AAAAAAAAAAAAAAAAAAAAAAAAA" (25 A's) in 16 slots:

Buffer (16 slots):              OVERFLOW ZONE (other memory):
┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
│ A │ A │ A │ A │ A │ A │ A │ A │ A │ A │ A │ A │ A │ A │ A │ A │ A │ A │ A │ A │ A │ A │ A │ A │ A │
└───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
                                                                ▲
                                                                │
                                            The extra letters spill over into
                                            memory that belongs to other data!
```

### The Stack: Where Local Variables Live

When a function runs, it needs temporary storage space for its local variables. This space comes from a region of memory called **the stack**. The stack is organized like a tower of trays in a cafeteria—you add trays to the top and remove them from the top.

```
THE STACK (grows downward in memory):

         High Memory Addresses
    ┌─────────────────────────────────┐
    │  Return Address                 │ ← Where to go when function ends
    ├─────────────────────────────────┤
    │  Saved Frame Pointer (EBP)      │ ← Helps manage stack frames
    ├─────────────────────────────────┤
    │  Local Variable 1               │
    ├─────────────────────────────────┤
    │  Local Variable 2               │
    ├─────────────────────────────────┤
    │  Buffer (our 16-char array)     │ ← Data is written here
    ├─────────────────────────────────┤
    │        ... more ...             │
    └─────────────────────────────────┘
         Low Memory Addresses
```

**The Key Insight**: When we overflow a buffer on the stack, we overwrite whatever is stored ABOVE it in the stack diagram. This includes the **return address**—the memory location where the CPU should jump when the current function finishes.

### How Attackers Exploit Buffer Overflows

1. **Find a vulnerable buffer**: The attacker discovers that `GetMachineName()` copies a computer name into a 16-character buffer without checking the length.

2. **Craft malicious input**: Instead of a normal computer name like "WEBSERVER1", the attacker sends:
   ```
   \\AAAAAAAAAAAAAAAAAAAA[shellcode][return_address]\share\file
   ```

3. **Overflow overwrites the return address**: When the function copies this long string, it overflows the buffer and overwrites the return address with an address chosen by the attacker.

4. **Hijack program execution**: When the function tries to return, instead of going back to the normal calling code, it jumps to the attacker's **shellcode**—a small program embedded in the attack payload.

```
BEFORE OVERFLOW:                      AFTER OVERFLOW:
┌─────────────────────┐               ┌─────────────────────┐
│ Return: 0x77E81234  │               │ Return: 0x0012FF88  │ ← Points to shellcode!
├─────────────────────┤               ├─────────────────────┤
│ Saved EBP           │               │ AAAA (0x41414141)   │ ← Corrupted
├─────────────────────┤               ├─────────────────────┤
│ Buffer[15]          │               │ AAAA                │
│ Buffer[14]          │               │ AAAA                │
│    ...              │               │ ...                 │
│ Buffer[0]           │               │ AAAA                │
└─────────────────────┘               └─────────────────────┘
```

### Why Was This Code Vulnerable?

The vulnerable code in `GetMachineName()` uses a simple **while loop** to copy characters:

```c
while ( *pwszTemp != L'\\' )
    *pwszServerName++ = *pwszTemp++;
```

This code says: "Keep copying characters until you find a backslash." But it never asks: "Have I run out of room in the destination buffer?" It's like telling someone to keep putting letters in mailboxes until they see a red envelope—but there are no red envelopes in the pile.

**The Safe Alternative** would be:
```c
int count = 0;
while ( *pwszTemp != L'\\' && count < MAX_COMPUTERNAME_LENGTH )
{
    *pwszServerName++ = *pwszTemp++;
    count++;
}
```

This version adds a **bounds check**: it stops copying either when it finds a backslash OR when it has copied the maximum allowed number of characters.

### The Blaster Worm: Real-World Impact

In August 2003, just three weeks after Microsoft released a patch for this vulnerability, an 18-year-old wrote the **Blaster worm** (also called "LoveSan" or "MSBlast"). The worm:

1. **Scanned the internet** for computers with port 135 open
2. **Exploited MS03-026** to run code on vulnerable machines
3. **Downloaded itself** to the victim computer
4. **Repeated the process** to spread further

Within days, hundreds of thousands of computers were infected. The worm contained this message:
```
I just want to say LOVE YOU SAN!!
billy gates why do you make this possible? Stop making money and fix your software!!
```

### Key Lessons for Programmers

1. **Never trust input sizes**: Always validate that input data fits in your buffers before copying.

2. **Use safe string functions**: Instead of `strcpy()` or manual loops, use `strncpy()`, `StringCchCopy()`, or other bounds-checking functions.

3. **Defense in depth**: Modern systems add multiple protections:
   - **Stack canaries**: Secret values placed between buffers and return addresses that are checked before returning
   - **ASLR (Address Space Layout Randomization)**: Randomizes memory locations so attackers can't predict where to jump
   - **DEP (Data Execution Prevention)**: Marks the stack as non-executable so shellcode can't run there

4. **Patch promptly**: The window between patch release and worm outbreak was only 26 days. Organizations that patched quickly were protected.

### Glossary

| Term | Definition |
|------|------------|
| **Buffer** | A fixed-size region of memory used to store data |
| **Stack** | Memory region where function local variables and return addresses are stored |
| **Return Address** | Memory location where execution should continue after a function ends |
| **Shellcode** | Small piece of code injected by an attacker, usually to spawn a command shell |
| **RPC** | Remote Procedure Call—a way for programs to execute functions on remote computers |
| **DCOM** | Distributed Component Object Model—Microsoft's technology for communication between software components across a network |
| **Worm** | Self-propagating malware that spreads automatically without user interaction |

---

## Vulnerability Location

| Component | Path |
|-----------|------|
| RPC Interface Definition | `com/ole32/idl/public/remact.idl:43` |
| RPC Entry Point | `com/ole32/dcomss/olescm/remactif.cxx:30` (`_RemoteActivation`) |
| Path Processing | `com/ole32/dcomss/olescm/remactif.cxx:390` (`GetServerPath`) |
| **Vulnerable Function** | `com/ole32/dcomss/olescm/actmisc.cxx:18` (`GetMachineName`) |
| **Vulnerable Code** | `com/ole32/dcomss/olescm/actmisc.cxx:118-119` |

---

## Attack Vector

The vulnerability is exploitable remotely via the DCOM RPC interface:

```
┌─────────────────────┐
│   Remote Attacker   │
└──────────┬──────────┘
           │
           ▼ TCP 135 (RPC Endpoint Mapper)
┌──────────────────────────────────────────────────────────────────────┐
│                    DCOMSS / RPCSS Service                            │
│                  (runs as LOCAL SYSTEM)                              │
└──────────┬───────────────────────────────────────────────────────────┘
           │ IActivation::RemoteActivation RPC
           ▼
┌──────────────────────────────────────────────────────────────────────┐
│  _RemoteActivation()                                                  │
│  com/ole32/dcomss/olescm/remactif.cxx:30                             │
│                                                                       │
│  Receives attacker-controlled pwszObjectName parameter               │
└──────────┬───────────────────────────────────────────────────────────┘
           │ If pwszObjectName is UNC path (\\server\share\...)
           ▼
┌──────────────────────────────────────────────────────────────────────┐
│  GetServerPath()                                                      │
│  com/ole32/dcomss/olescm/remactif.cxx:390                            │
│                                                                       │
│  Calls GetMachineName() to extract server from UNC path              │
└──────────┬───────────────────────────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────────────────────────────┐
│  GetMachineName()              ◄── STACK BUFFER OVERFLOW             │
│  com/ole32/dcomss/olescm/actmisc.cxx:18                              │
│                                                                       │
│  Copies machine name to 16-byte stack buffer without bounds check    │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Code Analysis

### 1. RPC Interface Definition

The `RemoteActivation` RPC method accepts a `pwszObjectName` parameter that is attacker-controlled:

**File:** `com/ole32/idl/public/remact.idl:43-65`

```c
interface IActivation
{
    error_status_t RemoteActivation(
        [in] handle_t                               hRpc,
        [in] ORPCTHIS                              *ORPCthis,
        [out] ORPCTHAT                             *ORPCthat,
        [in] GUID                                  *Clsid,
        [in, string, unique] WCHAR                 *pwszObjectName,  // ◄── ATTACKER CONTROLLED
        [in, unique] MInterfacePointer             *pObjectStorage,
        [in] DWORD                                  ClientImpLevel,
        [in] DWORD                                  Mode,
        [in,range(1,MAX_REQUESTED_INTERFACES)]DWORD Interfaces,
        [in,unique,size_is(Interfaces)] IID        *pIIDs,
        [in,range(0,MAX_REQUESTED_PROTSEQS)]unsigned short cRequestedProtseqs,
        [in, size_is(cRequestedProtseqs)]
               unsigned short                       aRequestedProtseqs[],
        [out] OXID                                 *pOxid,
        [out] DUALSTRINGARRAY                     **ppdsaOxidBindings,
        [out] IPID                                 *pipidRemUnknown,
        [out] DWORD                                *pAuthnHint,
        [out] COMVERSION                           *pServerVersion,
        [out] HRESULT                              *phr,
        [out,size_is(Interfaces)] MInterfacePointer **ppInterfaceData,
        [out,size_is(Interfaces)] HRESULT          *pResults
        );
}
```

**Security Issue:** The `pwszObjectName` parameter is a wide string with no length restrictions enforced by the IDL. An attacker can send an arbitrarily long UNC path.

---

### 2. RPC Entry Point

**File:** `com/ole32/dcomss/olescm/remactif.cxx:30-51`

```c
error_status_t _RemoteActivation(
    handle_t            hRpc,
    ORPCTHIS           *ORPCthis,
    ORPCTHAT           *ORPCthat,
    GUID               *Clsid,
    WCHAR              *pwszObjectName,    // ◄── Attacker-controlled input
    MInterfacePointer  *pObjectStorage,
    DWORD               ClientImpLevel,
    DWORD               Mode,
    DWORD               Interfaces,
    IID                *pIIDs,
    unsigned short      cRequestedProtseqs,
    unsigned short      aRequestedProtseqs[],
    OXID               *pOxid,
    DUALSTRINGARRAY   **ppdsaOxidBindings,
    IPID               *pipidRemUnknown,
    DWORD              *pAuthnHint,
    COMVERSION         *pServerVersion,
    HRESULT            *phr,
    MInterfacePointer **ppInterfaceData,
    HRESULT            *pResults )
{
    // ... parameter validation ...

    if (ActParams.MsgType == GETPERSISTENTINSTANCE)
    {
        // ...
        if ( pwszObjectName )
        {
            WCHAR *oldName = pwszObjectName;
            *phr = GetServerPath( pwszObjectName, &pwszObjectName);  // ◄── CALLS VULNERABLE PATH
            // ...
        }
    }
    // ...
}
```

**Note:** When `pwszObjectName` is provided and the message type is `GETPERSISTENTINSTANCE`, the code calls `GetServerPath()` with the attacker-controlled path.

---

### 3. Path Processing Function

**File:** `com/ole32/dcomss/olescm/remactif.cxx:390-468`

```c
HRESULT GetServerPath(
    WCHAR *     pwszPath,
    WCHAR **    pwszServerPath )
{
    WCHAR * pwszFinalPath;

    ASSERT(pwszPath != NULL);
    ASSERT(pwszServerPath != NULL);

    pwszFinalPath = pwszPath;
    *pwszServerPath = pwszPath;

    if ( (pwszPath[0] == L'\\') && (pwszPath[1] == L'\\') )
    {
        WCHAR           wszMachineName[MAX_COMPUTERNAME_LENGTH+1];  // ◄── 16 BYTES ONLY!
        WCHAR *         pwszShareName;
        WCHAR *         pwszShareEnd;
        PSHARE_INFO_2   pShareInfo;
        NET_API_STATUS  Status;
        HRESULT         hr;

        // It's already UNC so this had better succeed.
        hr = GetMachineName(
                    pwszPath,
                    wszMachineName      // ◄── PASSES SMALL BUFFER
#ifdef DFSACTIVATION
                    ,FALSE
#endif
                    );

        if ( FAILED(hr) )
            return hr;

        // ... rest of function ...
    }
    // ...
}
```

**Key Points:**
- Declares `wszMachineName[MAX_COMPUTERNAME_LENGTH+1]` - only **16 bytes** (wide chars = 32 bytes)
- Passes this small buffer to `GetMachineName()` along with attacker-controlled `pwszPath`
- No length validation before the call

---

### 4. The Vulnerable Function

**File:** `com/ole32/dcomss/olescm/actmisc.cxx:18-128`

```c
HRESULT GetMachineName(
    WCHAR * pwszPath,
    WCHAR   wszMachineName[MAX_COMPUTERNAME_LENGTH+1]  // Buffer size: 16 wide chars
#ifdef DFSACTIVATION
    ,BOOL   bDoDfsConversion
#endif
    )
{
    WCHAR * pwszServerName;
    BYTE    Buffer[sizeof(REMOTE_NAME_INFO)+MAX_PATH*sizeof(WCHAR)];
    DWORD   BufferSize = sizeof(Buffer);
    WCHAR   Drive[4];
    DWORD   Status;

    //
    // Extract the server name from the file's path name.
    //
    if ( pwszPath[0] != L'\\' || pwszPath[1] != L'\\' )
    {
        // Handle drive letter paths...
        // ...
    }

#ifdef DFSACTIVATION
    // DFS path handling...
    // ...
#endif

    // Skip the "\\".
    LPWSTR pwszTemp = pwszPath + 2;      // Points to start of machine name

    pwszServerName = wszMachineName;      // Points to destination buffer

    // ════════════════════════════════════════════════════════════════════════
    // VULNERABLE CODE - Lines 118-119
    // ════════════════════════════════════════════════════════════════════════
    while ( *pwszTemp != L'\\' )
        *pwszServerName++ = *pwszTemp++;   // ◄── NO BOUNDS CHECK!
    // ════════════════════════════════════════════════════════════════════════

    *pwszServerName = 0;

    return S_OK;
}
```

---

## The Vulnerability Explained

### Root Cause

The vulnerability is a **stack buffer overflow** caused by an unbounded string copy operation.

### The Flaw in Detail

1. **Buffer Size:** `MAX_COMPUTERNAME_LENGTH` is defined as **15** (from `base/published/winbase.w:7487`):
   ```c
   #define MAX_COMPUTERNAME_LENGTH 15
   ```
   So `wszMachineName[MAX_COMPUTERNAME_LENGTH+1]` = **16 wide characters** = **32 bytes**

2. **The Vulnerable Loop:**
   ```c
   while ( *pwszTemp != L'\\' )
       *pwszServerName++ = *pwszTemp++;
   ```

   This loop:
   - Starts at character position 2 in the path (after `\\`)
   - Copies characters until it finds a backslash `\`
   - **Has NO bounds checking** on the destination buffer
   - Continues copying regardless of buffer size

3. **Attack Scenario:**
   - Attacker sends: `\\AAAAAAAAAAAAAAAAAAAAAAAAAAAA...(hundreds of A's)...\share\file`
   - The loop copies all the `A` characters into the 16-character buffer
   - Stack overflow occurs, overwriting return address and other stack data

### Comparison: Safe vs. Vulnerable Code

**Vulnerable (Original):**
```c
while ( *pwszTemp != L'\\' )
    *pwszServerName++ = *pwszTemp++;
```

**Safe (Patched):**
```c
int count = 0;
while ( *pwszTemp != L'\\' && count < MAX_COMPUTERNAME_LENGTH )
{
    *pwszServerName++ = *pwszTemp++;
    count++;
}
```

Or using safe string functions:
```c
lstrcpynW(wszMachineName, pwszPath + 2, MAX_COMPUTERNAME_LENGTH + 1);
// Then find and truncate at first backslash
```

---

## Memory Layout During Overflow

```
Stack (high addresses at top):
┌─────────────────────────────────────────────────────────────────┐
│                     Return Address                               │ ◄── Overwritten
├─────────────────────────────────────────────────────────────────┤
│                     Saved EBP                                    │ ◄── Overwritten
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│              Other Local Variables                               │ ◄── Overwritten
│              (Drive[4], BufferSize, Status, etc.)               │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│              Buffer[sizeof(REMOTE_NAME_INFO)+MAX_PATH*2]        │
│              (Large buffer - may absorb some overflow)          │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│              wszMachineName[16]                                  │ ◄── 32-byte buffer
│              (MAX_COMPUTERNAME_LENGTH+1 wide chars)             │    starts here
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │
                    Overflow writes upward
                    through stack frame
```

---

## Exploitation

### Attack Requirements

- **Network Access:** TCP port 135 (DCE/RPC Endpoint Mapper)
- **Authentication:** None required
- **User Interaction:** None required
- **Privileges Gained:** LOCAL SYSTEM (RPCSS/DCOMSS service context)

### Exploit Payload Construction

A typical exploit crafts a DCOM activation request with a malicious UNC path:

```
RPC Request to IActivation::RemoteActivation
├── ORPCthis: [standard ORPC header]
├── Clsid: {any valid CLSID}
├── pwszObjectName: "\\AAAA...AAA<shellcode><return_addr>\share\file"
│                      └── Very long machine name causes overflow
├── Mode: MODE_GET_CLASS_OBJECT
└── ... other parameters ...
```

### Blaster Worm Payload

The Blaster worm (August 2003) used this vulnerability to:

1. Connect to TCP port 135 on target systems
2. Send crafted `RemoteActivation` RPC request
3. Overflow the buffer with shellcode
4. Execute code to:
   - Download `msblast.exe` via TFTP from the infecting host
   - Install itself in the registry for persistence
   - Scan for new targets on random IP ranges
   - Launch DDoS attack against `windowsupdate.com` on specific dates

### Shellcode Execution

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Attacker sends RPC request with long machine name        │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. GetMachineName() copies into 32-byte buffer              │
│    - Continues past buffer boundary                          │
│    - Overwrites saved EBP, return address                    │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Function returns                                          │
│    - Pops corrupted EBP                                      │
│    - RET jumps to attacker-controlled address                │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Shellcode executes with SYSTEM privileges                │
│    - Downloads and executes worm payload                     │
│    - Or executes arbitrary attacker code                     │
└─────────────────────────────────────────────────────────────┘
```

---

## The Blaster Worm

MS03-026 was exploited by the infamous **Blaster worm** (also known as MSBlast, Lovesan, or W32.Blaster), which caused widespread damage in August 2003.

### Blaster Characteristics

| Attribute | Value |
|-----------|-------|
| First Seen | August 11, 2003 |
| Peak Infections | ~400,000+ systems |
| Targets | Windows 2000, XP, Server 2003 |
| Propagation | TCP 135 (RPC), TCP 4444 (shell), UDP 69 (TFTP) |
| Payload | DDoS against windowsupdate.com |

### Blaster Timeline

| Date | Event |
|------|-------|
| July 16, 2003 | Microsoft releases MS03-026 patch |
| July 25, 2003 | Proof-of-concept exploit published (xfocus) |
| August 11, 2003 | Blaster worm first detected in the wild |
| August 12-13, 2003 | Rapid global spread; major networks affected |
| August 16, 2003 | Scheduled DDoS against windowsupdate.com (mitigated) |
| August 18, 2003 | Welchia/Nachi "good worm" appears (patches systems) |
| August 29, 2003 | 18-year-old Jeffrey Parson arrested for Blaster.B variant |

### Blaster's Embedded Message

The worm contained this message in its binary:
```
I just want to say LOVE YOU SAN!!
billy gates why do you make this possible? Stop making money and fix your software!!
```

### Why It Was So Devastating

1. **Zero-Day Window:** Exploit code published ~3 weeks after patch release
2. **Pre-auth RCE:** No credentials needed, no user interaction
3. **SYSTEM Privileges:** Complete system compromise
4. **Wormable:** Self-propagating across the internet
5. **Default Exposure:** RPC service enabled and network-accessible by default
6. **Slow Patching:** Many systems unpatched despite available fix

---

## Related Vulnerabilities

MS03-026 was part of a series of critical RPC vulnerabilities:

| Bulletin | CVE | Description |
|----------|-----|-------------|
| MS03-026 | CVE-2003-0352 | DCOM RPC buffer overflow (this vulnerability) |
| MS03-039 | CVE-2003-0715 | RPCSS buffer overflow (similar, different function) |
| MS04-012 | CVE-2003-0807 | RPC Runtime Library vulnerability |

---

## Remediation

### Microsoft's Fix

The MS03-026 patch adds bounds checking to the `GetMachineName()` function:

1. Validates that the machine name component doesn't exceed `MAX_COMPUTERNAME_LENGTH`
2. Truncates or rejects overly long names
3. Uses safe string copy functions

### Mitigations

1. **Apply MS03-026 patch** (and all subsequent service packs)
2. **Block TCP 135** at network perimeter (and 139, 445 for full RPC blocking)
3. **Enable Windows Firewall** or host-based firewall
4. **Disable DCOM** if not needed:
   ```
   dcomcnfg.exe → Component Services → Computers → My Computer → Properties
   → Default Properties → Uncheck "Enable Distributed COM"
   ```
5. **Network segmentation** to limit lateral movement
6. **Intrusion Detection** - signatures for Blaster traffic patterns

---

## References

- [Microsoft Security Bulletin MS03-026](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-026)
- [CVE-2003-0352](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0352)
- [CERT Advisory CA-2003-20](https://www.cisa.gov/uscert/ncas/alerts/aa03-236a)
- [xfocus Original Advisory](http://www.xfocus.org/advisories/200307/3.html)
- [The Last Stage of Delirium Research Group Analysis](http://lsd-pl.net/special.html)

---

## Source Code References

| File | Line | Function/Element | Description |
|------|------|------------------|-------------|
| `com/ole32/idl/public/remact.idl` | 43 | `RemoteActivation` | RPC interface definition |
| `com/ole32/idl/public/remact.idl` | 48 | `pwszObjectName` | Attacker-controlled parameter |
| `com/ole32/dcomss/olescm/remactif.cxx` | 30 | `_RemoteActivation` | RPC entry point |
| `com/ole32/dcomss/olescm/remactif.cxx` | 193 | `GetServerPath()` call | Triggers vulnerable path |
| `com/ole32/dcomss/olescm/remactif.cxx` | 390 | `GetServerPath` | Allocates small buffer |
| `com/ole32/dcomss/olescm/remactif.cxx` | 404 | `wszMachineName` | 16-char stack buffer |
| `com/ole32/dcomss/olescm/remactif.cxx` | 412 | `GetMachineName()` call | Passes small buffer |
| `com/ole32/dcomss/olescm/actmisc.cxx` | 18 | `GetMachineName` | **Vulnerable function** |
| `com/ole32/dcomss/olescm/actmisc.cxx` | 118-119 | `while` loop | **Unbounded copy** |
| `base/published/winbase.w` | 7487 | `MAX_COMPUTERNAME_LENGTH` | Defined as 15 |

---

## Comparison with MS08-067

| Aspect | MS03-026 (Blaster) | MS08-067 (Conficker) |
|--------|-------------------|---------------------|
| Year | 2003 | 2008 |
| Service | DCOM RPC (RPCSS) | Server Service (srvsvc) |
| Port | TCP 135 | TCP 445 |
| Function | `GetMachineName()` | `ConvertPathMacros()` |
| Bug Type | Unbounded while loop | Pointer miscalculation |
| Buffer | 16 wide chars | MAX_PATH*2 stack buffer |
| Worm | Blaster | Conficker |
| Infections | ~400K | ~9-15M |
