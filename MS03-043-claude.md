# MS03-043 (CVE-2003-0717) Code Location Notes

## Executive Summary

MS03-043 is a heap buffer overflow vulnerability in the Windows Messenger Service that was exploited by multiple worms including Gaobot and Agobot. The vulnerability exists in the message text processing code where IBM end-of-line characters (0x14) are expanded to CR+LF (2 bytes), but the buffer size calculations don't properly account for this expansion when copying to a fixed-size alert buffer.

**Impact**: Unauthenticated remote code execution with SYSTEM privileges via UDP port 135 (RPC) or NetBIOS ports (137-139).

**Historical Significance**: This vulnerability was notable for being exploited via UDP, making it faster to propagate than TCP-based worms. The "net send" spam epidemic of the early 2000s also abused this service.

---

## Educational Overview: Character Expansion and Buffer Size Miscalculation

*This section explains the vulnerability as if giving a lecture to a high school computer science class.*

### The Problem: When One Becomes Two

Imagine you're writing a letter, and every time you see a special symbol (let's call it "¶"), you need to replace it with two words: "NEW LINE".

```
Original text (10 characters):
"Hello¶World"

After replacement (18 characters):
"HelloNEW LINEWorld"
```

If you prepared an envelope that could only hold 15 characters, you'd have a problem!

### The Messenger Service's Mistake

The Windows Messenger Service does something similar. When it receives a message containing the byte `0x14` (an old IBM end-of-line character), it replaces it with `\r\n` (carriage return + line feed):

```c
if(*text == '\024')     // If IBM end-of-line character (0x14)
{
    ++length;           // Oops! Counting AFTER we've already allocated!
    *cp++ = '\r';       // Write 1st byte
    *cp++ = '\n';       // Write 2nd byte
}
```

### The "Box Within a Box" Problem

Think of it like Russian nesting dolls:

```
Outer Box (alert_buf_ptr):
+--------------------------------------------------+
| STD_ALERT header (~200 bytes)                    |
+--------------------------------------------------+
| Message area (ALERT_MAX_DISPLAYED_MSG_SIZE=4096) |
+--------------------------------------------------+
| Extra space (2*TXTMAX + 2 = 258 bytes)           |
+--------------------------------------------------+
Total: ~4554 bytes

Inner Box (buffer in Msgtxtprint):
+--------------------------------------------------+
| Allocated: 2 * input_length + 1                  |
| But can EXPAND due to 0x14 → CR+LF conversion!   |
+--------------------------------------------------+
```

If the inner box becomes bigger than the space reserved for it in the outer box, it overflows!

### Why This Leads to Code Execution

```
Normal Heap Memory:
+----------------+----------------+----------------+
| alert_buf_ptr  | Other heap    | More heap      |
| (our buffer)   | data          | structures     |
+----------------+----------------+----------------+

After Overflow:
+----------------+----------------+----------------+
| alert_buf_ptr  | CORRUPTED!    | CORRUPTED!     |
| + overflow     | Attacker data | Function ptrs  |
+----------------+----------------+----------------+
                       |
                       v
            Attacker controls execution!
```

Heap overflows are particularly dangerous because the heap contains metadata and function pointers that attackers can corrupt to redirect program execution.

### The Timeline of Exploitation

```
October 15, 2003   Microsoft releases MS03-043 patch
         |
October 17, 2003   Proof-of-concept DoS exploit appears
         |
October 2003       Full RCE exploits circulate
         |
Late 2003          Gaobot/Agobot worms incorporate the exploit
         |
2003-2004          "Net send" spam becomes epidemic
         |
Windows Vista      Messenger Service disabled by default
```

---

## Call Path (NetBIOS Datagram to Buffer Overflow)

### 1. Message Reception

The Messenger Service receives messages via NetBIOS datagrams on UDP ports 137-139, or via the Mailslot RPC interface. Messages arrive as Server Message Blocks (SMB).

**Message Types**:
- SBM (Single-Block Message): Small messages that fit in one datagram
- MBB/MBT (Multi-Block Message): Large messages split across multiple datagrams

### 2. Message Logging Entry Point

**File**: `ds/netapi/svcdlls/msgsvc/server/meslog.c`
**Function**: `Msglogsbm()`
**Lines**: 536-659

```c
DWORD
Msglogsbm(
    LPSTR   from,       // Name of sender
    LPSTR   to,         // Name of recipient
    LPSTR   text,       // Text of message
    ULONG   SessionId   // Session Id
)
{
    // ...

    // Line 566-568: Allocate alert buffer
    bufSize = sizeof(STD_ALERT) +
              ALERT_MAX_DISPLAYED_MSG_SIZE +    // 4096 bytes
              (2*TXTMAX) + 2;                   // 258 bytes

    alert_buf_ptr = (PSTD_ALERT)LocalAlloc(LMEM_ZEROINIT, bufSize);

    // Line 578: Initialize length counter
    alert_len = 0;

    // Line 582: Get length from message
    length = SmbGetUshort( (PUSHORT)text);
    text += sizeof(short);

    // ... eventually calls Msgtxtprint() ...
}
```

**Buffer Size Breakdown**:
- `sizeof(STD_ALERT)` ≈ 200 bytes (timestamp + two WCHAR arrays)
- `ALERT_MAX_DISPLAYED_MSG_SIZE` = 4096 bytes
- `2*TXTMAX + 2` = 258 bytes
- **Total**: ~4554 bytes

### 3. Vulnerable Text Processing

**File**: `ds/netapi/svcdlls/msgsvc/server/mesprint.c`
**Function**: `Msgtxtprint()`
**Lines**: 497-584

```c
DWORD
Msgtxtprint(
    int     action,         // Alert, File, or Alert and file
    LPSTR   text,           // Pointer to text
    DWORD   length,         // Length of text
    HANDLE  file_handle     // Log file handle
)
{
    LPSTR   buffer;
    LPSTR   cp;
    DWORD   i;

    // Line 524: Allocate buffer - 2x size for "paranoid" expansion
    buffer = LocalAlloc( LMEM_FIXED, 2 * length + 1);

    cp = buffer;

    // Lines 536-557: Character expansion loop
    for(i = length; i != 0; --i)
    {
        if(*text == '\024')              // Line 538: IBM end-of-line (0x14)
        {
            ++length;                     // Line 544: Increment length AFTER alloc!
            *cp++ = '\r';                 // Line 545: Carriage return
            *cp++ = '\n';                 // Line 546: Line feed
        }
        else
        {
            *cp++ = *text;                // Line 554: Copy as-is
        }
        ++text;
    }
    *cp = '\0';                          // Line 558: Null terminate

    if( action >= 0)
    {
        // Lines 566-570: THE VULNERABLE COPY
        if( alert_len < ALERT_MAX_DISPLAYED_MSG_SIZE + 1)  // Insufficient check!
        {
            memcpy( &alert_buf_ptr[alert_len], buffer, strlen(buffer));
            alert_len += (USHORT)strlen(buffer);
        }
    }

    LocalFree( buffer );
    return status;
}
```

### 4. Global Variables

**File**: `ds/netapi/svcdlls/msgsvc/server/mesprint.c`
**Lines**: 71-72

```c
LPSTR           alert_buf_ptr;    // Pointer to heap-allocated alert buffer
USHORT          alert_len;        // Currently used length of alert buffer
```

## The Vulnerability

### Root Cause Analysis

1. **Buffer Allocation**: `buffer = LocalAlloc(LMEM_FIXED, 2 * length + 1)` - Allocates twice the input length plus one byte for null terminator

2. **Character Expansion**: Each `0x14` byte becomes two bytes (`\r\n`), but the allocation was based on the original length

3. **Insufficient Bounds Check**: Line 566 only checks if `alert_len < ALERT_MAX_DISPLAYED_MSG_SIZE + 1`, but doesn't verify that `alert_len + strlen(buffer)` will fit

4. **Unsafe Copy**: The `memcpy()` at line 568 uses `strlen(buffer)` without checking if it exceeds available space

### Attack Scenario

```
Attacker crafts message:
+-----------------------------------------+
| 2000 bytes of 'A' + 2000 bytes of 0x14  |
+-----------------------------------------+
                    |
                    v
Initial allocation: 2 * 4000 + 1 = 8001 bytes (OK)
                    |
                    v
After expansion: 2000 + (2000 * 2) = 6000 bytes (still fits in buffer)
                    |
                    v
alert_buf_ptr has ~4354 bytes available after header
                    |
                    v
memcpy copies 6000 bytes → HEAP OVERFLOW!
```

### The Check That Doesn't Work

```c
if( alert_len < ALERT_MAX_DISPLAYED_MSG_SIZE + 1)  // alert_len < 4097
{
    memcpy( &alert_buf_ptr[alert_len], buffer, strlen(buffer));
    //      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //      This can write past end of alert_buf_ptr if strlen(buffer) is large!
}
```

The check only verifies that `alert_len` (the current position) is within bounds, not that the **copy operation** will stay within bounds.

## Constants and Definitions

**File**: `ds/netapi/svcdlls/msgsvc/server/msrv.h`

```c
#define TXTMAX                          128     // Line 35
#define ALERT_MAX_DISPLAYED_MSG_SIZE    4096    // Line 82
```

**File**: `public/sdk/inc/lmalert.h` (Lines 64-68)

```c
typedef struct _STD_ALERT {
    DWORD  alrt_timestamp;              // 4 bytes
    WCHAR  alrt_eventname[EVLEN + 1];   // (16+1)*2 = 34 bytes
    WCHAR  alrt_servicename[SNLEN + 1]; // (80+1)*2 = 162 bytes
} STD_ALERT;                            // Total: ~200 bytes
```

## Trigger Summary

1. **Connect** to target via UDP port 135 (RPC endpoint mapper) or NetBIOS ports (137-139)
2. **Send** a Messenger Service datagram containing:
   - Valid SMB message header
   - Sender and recipient names
   - Message body with many `0x14` bytes
3. **Calculation**: Body with N regular chars + M `0x14` bytes becomes `N + 2M` bytes after expansion
4. **Overflow condition**: When `N + 2M > available_alert_space` (~4354 bytes)
5. **Result**: Heap buffer overflow in `alert_buf_ptr`, potentially overwriting adjacent heap structures

## Attack Vector Details

Unlike TCP-based vulnerabilities, MS03-043 can be exploited via UDP:
- **Faster scanning**: UDP is connectionless, allowing rapid spraying
- **Firewall evasion**: Some firewalls treated UDP differently
- **Spoofable source**: UDP source addresses can be forged

## Fix Considerations

1. **Proper bounds checking**: Before `memcpy`, verify `alert_len + strlen(buffer) <= MAX_BUFFER_SIZE`:
   ```c
   size_t copy_len = strlen(buffer);
   if (alert_len + copy_len <= ALERT_MAX_DISPLAYED_MSG_SIZE) {
       memcpy(&alert_buf_ptr[alert_len], buffer, copy_len);
       alert_len += copy_len;
   }
   ```

2. **Pre-calculate expanded size**: Before processing, count `0x14` bytes and ensure expanded size fits

3. **Use safe string functions**: Replace `memcpy` with `memcpy_s` or `StringCchCopyN`

4. **Disable by default**: Microsoft eventually disabled the Messenger Service by default in Windows XP SP2 and later

## Cross-Check Notes

*Codex verification identified the following nuances:*

1. **Inner buffer allocation is actually safe**: The `LocalAlloc(2 * length + 1)` already accounts for worst-case 0x14 expansion. The `++length` inside the loop is unused after allocation.

2. **Real overflow cause**: The overflow occurs because `memcpy` copies `strlen(buffer)` bytes without verifying that `alert_len + strlen(buffer)` fits within `bufSize` (~4554 bytes). The guard only checks `alert_len < 4097`, not the total after copy.

3. **0x14 expansion is not the core issue**: Any sufficiently long message (RPC allows far more than 4KB) can overflow the buffer, with or without 0x14 content. The expansion merely amplifies message size.

4. **Additional unsafe operations**:
   - `Msghdrprint()` also performs `memcpy` into `alert_buf_ptr` without bounds checking
   - The `sizeof(STD_ALERT)` region is effectively overwritten since `alert_len` starts at 0
   - No length clamping from the SMB/RPC path before calling message handlers

5. **RPC attack vector**: Messages via RPC (msgapi.c:1432-1500) have no length validation, allowing arbitrarily large payloads to trigger overflow.

## References

- Microsoft Security Bulletin MS03-043
- CVE-2003-0717
- [CERT VU#575892](https://www.kb.cert.org/vuls/id/575892)
- [Exploit-DB: MS03-043](https://www.exploit-db.com/exploits/23247)
- Discovered by: Last Stage of Delirium Research Group

Sources:
- [CVE Details - CVE-2003-0717](https://www.cvedetails.com/cve/CVE-2003-0717/)
- [Trend Micro Threat Encyclopedia](https://www.trendmicro.com/vinfo/be/threat-encyclopedia/vulnerability/686/microsoft-windows-messenger-service-buffer-overrun)
