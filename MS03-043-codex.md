# MS03-043 (CVE-2003-0717) Code Location Notes

## Overview
Heap overflow in Messenger Service alert handling: incoming text is expanded (0x14 → CR+LF), but the expanded length is copied into a fixed alert buffer without sufficient bounds checking.

## Call Path (Message Reception to Buffer Overflow)
1. `Msglogsbm()` allocates alert buffer and dispatches text  
   - `ds/netapi/svcdlls/msgsvc/server/meslog.c:536-579`  
   - Buffer sizing: `bufSize = sizeof(STD_ALERT) + ALERT_MAX_DISPLAYED_MSG_SIZE + (2*TXTMAX) + 2;` then `alert_buf_ptr = LocalAlloc(LMEM_ZEROINIT, bufSize); alert_len = 0;`  
   - Pulls message length from network (`length = SmbGetUshort((PUSHORT)text)`) and, when logging is off, calls `Msgtxtprint(1, text, length, 0)`.
2. `Msgtxtprint()` builds an intermediate text buffer  
   - `ds/netapi/svcdlls/msgsvc/server/mesprint.c:500-569`  
   - Allocates `buffer = LocalAlloc(LMEM_FIXED, 2 * length + 1);` to allow growth during translation.
3. Character expansion (0x14 → CR+LF) doubles size without tightening limits  
   - `ds/netapi/svcdlls/msgsvc/server/mesprint.c:538-546`  
   - Snippet:  
     ```c
     if (*text == '\024') {    // IBM EOL
         ++length;             // track growth
         *cp++ = '\r';
         *cp++ = '\n';
     } else {
         *cp++ = *text;
     }
     ```
   - Result: `strlen(buffer)` can exceed the original `length` and the alert buffer slack.
4. Insufficient check and unsafe copy into alert buffer (heap overflow)  
   - `ds/netapi/svcdlls/msgsvc/server/mesprint.c:566-569`  
   - Snippet:  
     ```c
     if (alert_len < ALERT_MAX_DISPLAYED_MSG_SIZE + 1) {
         memcpy(&alert_buf_ptr[alert_len], buffer, strlen(buffer));
         alert_len += (USHORT)strlen(buffer);
     }
     ```
   - The guard only tests the current `alert_len`; it never ensures `alert_len + strlen(buffer)` fits within `bufSize` (`sizeof(STD_ALERT) + ALERT_MAX_DISPLAYED_MSG_SIZE + 2*TXTMAX + 2`). With expanded text >4096 bytes, `memcpy` overruns `alert_buf_ptr` on the heap.

## Trigger Summary
Send a NetBIOS/SMB single-block message (NetMessage/SMB_COM_SEND_MESSAGE datagram over UDP 138 or session 139) containing a long run of `0x14` bytes. The translation doubles these to CR+LF, `strlen(buffer)` grows past 4096, the weak check at line 566 passes, and the `memcpy` overflows the heap-backed alert buffer in the Messenger service (running as LocalSystem).

## Fix Considerations
- Compute expanded length upfront; enforce `alert_len + expanded_len <= ALERT_MAX_DISPLAYED_MSG_SIZE` (and the full `bufSize`) before copying.
- Stop mutating `length` mid-loop; track `expanded_len` separately to avoid misestimation.
- Replace the raw `memcpy` with a bounded copy (`min()` against remaining buffer space) or drop/truncate messages that would exceed the limit.
- Validate incoming `length` (from `SmbGetUshort`) against a maximum that accounts for worst-case expansion before entering `Msgtxtprint`.