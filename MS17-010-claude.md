# MS17-010 (CVE-2017-0144, "EternalBlue") Code Location Notes

## Executive Summary

MS17-010, known as "EternalBlue," is a critical vulnerability in the Windows SMBv1 server that was famously exploited by the WannaCry and NotPetya ransomware outbreaks in May and June 2017. The vulnerability was originally developed as an exploit by the NSA's Equation Group and was leaked by the Shadow Brokers hacking group in April 2017.

The vulnerability exists in the handling of SMB Transaction requests that include Extended Attributes (EAs). A type confusion bug allows an attacker to cause a kernel pool buffer overflow by sending specially crafted SMB packets to port 445.

**Impact**: Unauthenticated remote code execution with kernel privileges on any Windows system with SMBv1 enabled.

**Historical Significance**: This vulnerability enabled the largest ransomware outbreaks in history, affecting hundreds of thousands of systems worldwide, including hospitals, banks, and critical infrastructure.

---

## Educational Overview: Integer Type Confusion and Memory Corruption

*This section explains the vulnerability as if giving a lecture to a high school computer science class.*

### What Are Data Types and Why Do They Matter?

In programming, we store numbers in variables that have different "sizes" - like different sized containers for water:

```
UCHAR  (unsigned char)   = 1 byte  = can hold 0 to 255
USHORT (unsigned short)  = 2 bytes = can hold 0 to 65,535
ULONG  (unsigned long)   = 4 bytes = can hold 0 to 4,294,967,295
```

Think of it like measuring cups:
- A 1-cup measure (UCHAR) can only hold 1 cup
- A 2-cup measure (USHORT) can hold up to 2 cups
- A 4-cup measure (ULONG) can hold up to 4 cups

**The problem**: What happens if you try to pour 4 cups of water into a 2-cup measure? You lose 2 cups - they "overflow" and spill out.

### The Type Confusion Bug Explained

In the vulnerable code, there's a structure that tracks the size of a data list:

```c
typedef struct _FEALIST {
    _ULONG( cbList );   // 4-byte number - the "size" field
    FEA list[1];        // The actual data
} FEALIST;
```

The `cbList` field is a 4-byte number (ULONG) that stores how big the list is. But look at what happens in the vulnerable code:

```c
SmbPutUshort( &FeaList->cbList, PTR_DIFF_SHORT(fea, FeaList) );
```

This writes a **2-byte** (USHORT) value into a **4-byte** (ULONG) field!

### The "Bucket with Two Labels" Analogy

Imagine you have a bucket that holds water, and there's a label on it that says how much water is inside. Now imagine two scenarios:

**Scenario 1 - Normal Case (ULONG to ULONG)**:
- You have a 4-digit label: `____`
- You pour 5000 mL of water in
- Label reads: `5000`
- Everything works correctly!

**Scenario 2 - The Bug (USHORT to ULONG)**:
- You have a 4-digit label, but someone only updates the **last 2 digits**
- Original label: `1234` (representing 1234 mL)
- You pour out water until only 50 mL remains
- But the update only changes the last 2 digits: `12` stays, `34` becomes `50`
- Label now reads: `1250` instead of `0050`
- The bucket says it has 1250 mL, but actually only has 50 mL!

This is exactly what happens in EternalBlue. The attacker can manipulate the system into thinking a buffer is a different size than it actually is.

### From Type Confusion to System Compromise

Here's how an attacker exploits this:

1. **Send crafted data**: Attacker sends a specially designed SMB packet to the server
2. **Trigger the bug**: The server processes the packet and writes only 2 bytes to the 4-byte size field
3. **Size mismatch**: Now the kernel thinks a buffer is larger (or smaller) than it really is
4. **Memory corruption**: When the kernel later uses this buffer, it reads/writes past its actual boundaries
5. **Code execution**: The attacker carefully controls what gets written where, hijacking program flow

### Real-World Impact: Why This Bug Was So Devastating

```
           The EternalBlue Timeline

    2013 (est.)  NSA develops EternalBlue exploit
         |
    April 2017   Shadow Brokers leak NSA tools
         |
    May 12, 2017 WannaCry infects 230,000+ computers
         |                in 150 countries
         |
    June 2017    NotPetya causes $10+ billion damage
         |                worldwide
         |
    Today        Still being used in attacks
```

**WannaCry infected**:
- UK National Health Service (NHS) - hospitals had to turn away patients
- FedEx, Telefonica, Deutsche Bahn
- 230,000+ computers in 150 countries

**NotPetya caused**:
- $10+ billion in total damages (largest cyberattack in history)
- Maersk (shipping): $300 million loss
- Merck (pharmaceutical): $870 million loss
- FedEx (TNT Express): $400 million loss

### Why Was This Bug So Hard to Find?

The bug is subtle because:
1. The code looks correct at first glance
2. The type mismatch isn't obvious without understanding both structures
3. The vulnerability only manifests with specific input patterns
4. It requires understanding the kernel pool allocator to exploit

This is why security research and code review are so important - even experienced developers miss these kinds of bugs.

---

## Call Path (SMB Transaction to EA Handling)

### 1. SMB Transaction Entry

The vulnerability is triggered through SMB Transaction (or Transaction2) requests that include Extended Attributes:

- **Protocol**: SMBv1 over TCP port 445
- **Commands**: `SMB_COM_TRANSACTION2` (0x32) with subcommand `TRANS2_OPEN2` (0x00)
- **Authentication**: No authentication required (pre-auth vulnerability)

### 2. Transaction Processing

The SMB server receives the transaction and routes it to the appropriate handler based on the subcommand. For EA-related operations, this involves:

```
SMB Request (Port 445)
    |
    v
SrvSmbTransaction2 / SrvSmbNtTransaction
    |
    v
TRANS2_OPEN2 / TRANS2_SET_PATH_INFO subcommands
    |
    v
EA Processing Functions
```

### 3. Vulnerable Code Path: `base/fs/srv/ea.c`

**File**: `base/fs/srv/ea.c`

**Function 1: SrvOs2FeaListToNt** (Lines 261-401)

This function converts OS/2-format Extended Attribute lists to NT format:

```c
NTSTATUS
SrvOs2FeaListToNt (
    IN PFEALIST FeaList,
    OUT PFILE_FULL_EA_INFORMATION *NtFullEa,
    OUT PULONG BufferLength,
    OUT PUSHORT EaErrorOffset
    )
{
    // ...

    // Calculate size needed for NT format
    *BufferLength = SrvOs2FeaListSizeToNt( FeaList );  // <-- Calls vulnerable function

    // Allocate kernel pool buffer based on calculated size
    *NtFullEa = ALLOCATE_NONPAGED_POOL( *BufferLength, BlockTypeDataBuffer );

    // Convert FEAs - may overflow the allocated buffer!
    for ( fea = FeaList->list, ntFullEa = *NtFullEa, lastNtFullEa = ntFullEa;
          fea <= lastFeaStartLocation;
          fea = (PFEA)( (PCHAR)fea + sizeof(FEA) +
                        fea->cbName + 1 + SmbGetUshort( &fea->cbValue ) ) ) {

        ntFullEa = SrvOs2FeaToNt( ntFullEa, fea );  // <-- May write past buffer!
    }
    // ...
}
```

**Function 2: SrvOs2FeaListSizeToNt** (Lines 405-496) - THE VULNERABLE FUNCTION

```c
ULONG
SrvOs2FeaListSizeToNt (
    IN PFEALIST FeaList
    )
/*++
Routine Description:
    Get the number of bytes that would be required to represent the
    FEALIST in NT format.

    WARNING: This routine makes no checks on the size of the FEALIST
    buffer.  It is assumed that FeaList->cbList is a legitimate value.
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    This warning acknowledges the dangerous assumption!
--*/
{
    ULONG size = 0;
    PCHAR lastValidLocation;
    PFEA  fea;

    // Get the end of the buffer based on cbList (ULONG field)
    lastValidLocation = (PCHAR)FeaList + SmbGetUlong( &FeaList->cbList );

    // Iterate through FEAs
    for ( fea = FeaList->list;
          fea < (PFEA)lastValidLocation;
          fea = (PFEA)( (PCHAR)fea + sizeof(FEA) +
                          fea->cbName + 1 + SmbGetUshort( &fea->cbValue ) ) ) {

        // Validation check...
        if (variableBuffer >= lastValidLocation ||
            (variableBuffer + fea->cbName + 1 + SmbGetUshort(&fea->cbValue)) > lastValidLocation) {

            // THE BUG IS HERE - Line 477:
            // Writing USHORT (2 bytes) to ULONG (4 bytes) field!
            SmbPutUshort( &FeaList->cbList, PTR_DIFF_SHORT(fea, FeaList) );
            //            ^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^
            //            4-byte ULONG field  2-byte value written!
            break;
        }

        size += SmbGetNtSizeOfFea( fea );
    }

    return size;
}
```

**Function 3: SrvOs2FeaToNt** (Lines 500-562)

This function performs the actual memory copy that can overflow:

```c
PVOID
SrvOs2FeaToNt (
    OUT PFILE_FULL_EA_INFORMATION NtFullEa,
    IN PFEA Fea
    )
/*++
Routine Description:
    Converts a single OS/2 FEA to NT full EA style.
    This routine makes no checks on buffer overrunning--this is the
    responsibility of the calling routine.
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    Another dangerous comment - if size calculation is wrong, overflow occurs!
--*/
{
    PCHAR ptr;

    NtFullEa->Flags = Fea->fEA;
    NtFullEa->EaNameLength = Fea->cbName;
    NtFullEa->EaValueLength = SmbGetUshort( &Fea->cbValue );

    ptr = NtFullEa->EaName;
    RtlMoveMemory( ptr, (PVOID)(Fea+1), Fea->cbName );  // Copy EA name
    ptr += NtFullEa->EaNameLength;
    *ptr++ = '\0';

    // Copy the EA value - THIS IS WHERE OVERFLOW OCCURS
    RtlMoveMemory(
        ptr,
        (PCHAR)(Fea+1) + NtFullEa->EaNameLength + 1,
        NtFullEa->EaValueLength     // Can be attacker-controlled size!
        );

    // ...
}
```

## Data Structures

**FEA Structure** (Extended Attribute Entry):
```c
typedef struct _FEA {
    UCHAR fEA;                  // Flags (1 byte)
    UCHAR cbName;               // Length of EA name (1 byte)
    _USHORT( cbValue );         // Length of EA value (2 bytes)
} FEA;
// Total: 4 bytes header + variable name + variable value
```

**FEALIST Structure** (List of Extended Attributes):
```c
typedef struct _FEALIST {
    _ULONG( cbList );           // Total size of list (4 bytes) - THE KEY FIELD
    FEA list[1];                // Array of FEA entries
} FEALIST;
```

## The Type Confusion Vulnerability (Line 477)

The core vulnerability is at line 477 in `SrvOs2FeaListSizeToNt`:

```c
SmbPutUshort( &FeaList->cbList, PTR_DIFF_SHORT(fea, FeaList) );
```

**Analysis**:
1. `FeaList->cbList` is defined as `_ULONG( cbList )` - a 4-byte unsigned integer
2. `SmbPutUshort` writes only 2 bytes (USHORT)
3. `PTR_DIFF_SHORT` also produces a 2-byte value
4. Only the lower 2 bytes of the 4-byte `cbList` field are modified!

**Exploitation Scenario**:

1. Attacker sends FEALIST with `cbList = 0x10000` (65536 bytes)
2. Server calls `SrvOs2FeaListSizeToNt`
3. During validation, the check at line 468-469 fails for a malformed FEA
4. Line 477 executes: `SmbPutUshort(&FeaList->cbList, small_value)`
5. Only lower 2 bytes are written, so if small_value = 0x0100:
   - Before: `cbList = 0x00010000`
   - After:  `cbList = 0x00010100` (not `0x00000100`!)
6. The size calculation returns a small value
7. `SrvOs2FeaListToNt` allocates a small kernel pool buffer
8. But the loop uses the corrupted `cbList` (large value) to determine iteration bounds
9. `SrvOs2FeaToNt` writes past the allocated buffer = **KERNEL POOL OVERFLOW**

## Trigger Summary

1. **Connect** to SMB port 445 (no authentication needed)
2. **Send** SMB_COM_NEGOTIATE to establish connection
3. **Send** SMB_COM_SESSION_SETUP_ANDX (null session or anonymous)
4. **Send** SMB_COM_TREE_CONNECT_ANDX to IPC$ share
5. **Send** SMB_COM_TRANSACTION2 with:
   - Subcommand: TRANS2_OPEN2 or similar EA-using command
   - Crafted FEALIST where:
     - `cbList` has high bits set (e.g., 0x10000)
     - FEA entries crafted to trigger the type confusion
6. Server processes the malformed FEALIST
7. Type confusion corrupts `cbList` field
8. Buffer size mismatch leads to kernel pool overflow
9. Attacker controls pool overflow data for code execution

## Exploitation Details

The actual EternalBlue exploit chains multiple bugs:

1. **Bug 1**: The type confusion described above (USHORT to ULONG write)
2. **Bug 2**: An information disclosure to defeat ASLR
3. **Bug 3**: Kernel pool grooming to control adjacent allocations

The kernel pool overflow is used to:
1. Corrupt adjacent pool allocations (typically `SRVNET_BUFFER_HDR` objects)
2. Gain arbitrary read/write primitive
3. Overwrite function pointers or modify page table entries
4. Achieve kernel-mode code execution

## Historical Context

| Date | Event |
|------|-------|
| ~2013 | NSA Equation Group develops EternalBlue |
| March 14, 2017 | Microsoft releases MS17-010 patch |
| April 14, 2017 | Shadow Brokers release EternalBlue exploit |
| May 12, 2017 | WannaCry ransomware outbreak begins |
| June 27, 2017 | NotPetya (disguised as ransomware) attacks Ukraine |
| Present | Still actively exploited against unpatched systems |

## Fix Considerations

1. **Type-safe field updates**: Use `SmbPutUlong` when writing to `cbList`:
   ```c
   // Fixed version:
   SmbPutUlong( &FeaList->cbList, PTR_DIFF(fea, FeaList) );
   ```

2. **Bounds validation**: Add explicit size checks before buffer allocation:
   ```c
   if (*BufferLength > MAX_EA_BUFFER_SIZE) {
       return STATUS_INVALID_PARAMETER;
   }
   ```

3. **Defense in depth**:
   - Disable SMBv1 entirely (Microsoft recommendation)
   - Use kernel pool integrity checks
   - Implement Control Flow Guard (CFG)

4. **The actual Microsoft fix**: Microsoft's MS17-010 patch corrects the type mismatch by ensuring proper ULONG operations throughout the EA handling code path.

## References

- CVE-2017-0144 (EternalBlue)
- CVE-2017-0145 (EternalRomance)
- CVE-2017-0146 (EternalChampion)
- CVE-2017-0147 (EternalSynergy)
- MS17-010 Microsoft Security Bulletin
- Metasploit module: `exploit/windows/smb/ms17_010_eternalblue`
