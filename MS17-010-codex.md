# MS17-010 (CVE-2017-0144, "EternalBlue") Code Location Notes

## Overview
SMBv1 Transaction/Transaction2 handlers accept OS/2-style EA lists and translate them to NT EAs. When a malformed FEA range is detected, `SrvOs2FeaListSizeToNt` writes a 16-bit length into the 32-bit `FEALIST->cbList`, leaving attacker-controlled upper 16 bits intact. Later code trusts the 32-bit `cbList` to walk and copy FEAs into a small, nonpaged pool buffer sized from the truncated value, producing a kernel pool overflow/type confusion in `srv.sys`.

## Call Path (SMB Transaction to EA Handling)
1. **SMB protocol entry** (`base/fs/srv/smbtrans.c:390-408`): Transaction2 requests (e.g., `TRANS2_SET_PATH_INFORMATION`) are dispatched from the SMB_COM_TRANSACTION2 handler.
   ```c
   // base/fs/srv/smbtrans.c:390-408
   command = SmbGetUshort( &transaction->InSetup[0] );
   resultStatus = SrvTransaction2DispatchTable[ command ]( WorkContext );
   ```
2. **Transaction handling** (`base/fs/srv/srvdata.c:954-967`, `base/fs/srv/smbattr.c:3826-4180`): The Transaction2 dispatch table routes `TRANS2_SET_PATH_INFORMATION` to `SrvSmbSetPathInformation`, which opens the target file and, for EA updates, funnels untrusted EA blobs to `SrvSetOs2FeaList`.
   ```c
   // base/fs/srv/srvdata.c:958-967
   PSMB_TRANSACTION_PROCESSOR SrvTransaction2DispatchTable[] = {
       ...,
       SrvSmbSetPathInformation,   // TRANS2_SET_PATH_INFORMATION
       ...
   };
   // base/fs/srv/smbattr.c:3056-3180
   case SMB_INFO_QUERY_EA_SIZE:
       status = SrvSetOs2FeaList(
                    FileHandle,
                    (PFEALIST)Transaction->InData,
                    Transaction->DataCount,
                    &eaErrorOffset );
   ```
3. **EA conversion** (`base/fs/srv/ea.c:313-363`): `SrvOs2FeaListToNt` sizes the destination buffer from `SrvOs2FeaListSizeToNt`, then walks the FEA list using the (mutable) `cbList` field.
   ```c
   // base/fs/srv/ea.c:313-363
   *BufferLength = SrvOs2FeaListSizeToNt( FeaList );
   *NtFullEa = ALLOCATE_NONPAGED_POOL( *BufferLength, BlockTypeDataBuffer );
   lastFeaStartLocation = (PFEA)((PCHAR)FeaList +
                         SmbGetUlong(&FeaList->cbList) - sizeof(FEA) - 1);
   for (fea = FeaList->list; fea <= lastFeaStartLocation;
        fea = (PFEA)((PCHAR)fea + sizeof(FEA) +
                     fea->cbName + 1 + SmbGetUshort(&fea->cbValue))) {
       ...
       ntFullEa = SrvOs2FeaToNt( ntFullEa, fea );
   }
   ```
   Relevant structures defining the mixed-size fields that drive this logic live in `public/internal/base/inc/smbtypes.h:270-293` (`FEA` 16-bit `cbValue`, `FEALIST` 32-bit `cbList`).
4. **Bug (type confusion/overflow)** (`base/fs/srv/ea.c:466-478`): When a malformed FEA overflows the reported list, the code “shrinks” `cbList` with a 16-bit store, corrupting the 32-bit length and enabling an undersized allocation paired with an oversized walk/copy.
   ```c
   // base/fs/srv/ea.c:466-478
   if (variableBuffer >= lastValidLocation ||
       (variableBuffer + fea->cbName + 1 + SmbGetUshort(&fea->cbValue)) > lastValidLocation) {
       // attempts to clamp cbList but only writes 16 bits
       SmbPutUshort( &FeaList->cbList, PTR_DIFF_SHORT(fea, FeaList) );
       break;
   }
   ```
   The high 16 bits of `cbList` (from the attacker) remain, so `SmbGetUlong(&FeaList->cbList)` later sees a large value while `*BufferLength` stayed small, letting `SrvOs2FeaToNt` overflow the nonpaged pool buffer.

## Trigger Summary
Send an SMB_COM_TRANSACTION2 `TRANS2_SET_PATH_INFORMATION` (or any EA-setting path/file info op) with `InformationLevel` targeting EA update and a crafted OS/2 `FEALIST` in `Transaction->InData`. Use a bogus FEA whose `cbName/cbValue` pushes `variableBuffer + ...` past `lastValidLocation` so `SrvOs2FeaListSizeToNt` executes the `SmbPutUshort` path. Keep a large high word in `cbList` to drive later traversal, while the computed buffer length stays small, yielding a controllable kernel pool overflow during EA conversion.

## Fix Considerations
- Treat `cbList` as 32-bit: clear/overwrite all 4 bytes (or reject outright) when clamping; never partial-store with `SmbPutUshort`.
- Fail hard on inconsistent FEAs instead of mutating `cbList`; avoid continuing with partially validated data.
- Revalidate lengths before allocation and before each FEA copy, using 32-bit bounded arithmetic to cap against the actual request buffer size.
- Consider separating attacker-controlled `cbList` from internal walk state (copy to a local 32-bit length that cannot be attacker-reused across phases).