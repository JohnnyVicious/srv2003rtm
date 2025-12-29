# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Windows Server 2003 RTM source code (partial ~70% complete), patched to compile on modern Windows (including Windows 11). Uses Microsoft's internal "Razzle" build system.

## Build Commands

**Prerequisites:**
- Extract to `{drive}:\srv03rtm` (not C:, recommend D: to match RTM binaries)
- Run command prompt as Administrator
- Disable AV for faster builds
- Max 4 threads recommended: add `-M 4` to build commands

**Initialize build environment:**
```cmd
tools\razzle64.cmd free offline
```

**Build commands (run from razzle window):**
```cmd
build /cZP        # Clean build (or: bcz)
build /ZP         # Incremental build (or: bz)
bcz -M 4          # Clean build with 4-thread limit
```

**Build specific component:**
```cmd
cd base\ntos      # or use 'ntos' alias
bcz               # Clean build of just that component
```

**Postbuild (after build completes):**
```cmd
tools\postbuild.cmd              # Process all SKUs
tools\postbuild.cmd -sku:srv     # Single SKU only
tools\postbuild.cmd -full        # Fresh postbuild
tools\missing.cmd                # Integrate external binaries
```

**Create ISO:**
```cmd
tools\oscdimg.cmd srv   # Standard Edition
tools\oscdimg.cmd sbs   # Small Business Edition
tools\oscdimg.cmd ads   # Enterprise Edition
tools\oscdimg.cmd dtc   # Datacenter Edition
tools\oscdimg.cmd bla   # Web Edition
```

**Razzle options:**
- `free` - Production build (omit for checked/debug build)
- `chkkernel` - Checked kernel with free user-mode
- `no_opts` - Disable optimization (for debugging)
- `verbose` - Verbose build output
- `officialbuild` - Official build mode (requires BuildMachines.txt setup)

## Architecture

### Major Components

| Directory | Purpose |
|-----------|---------|
| `base/ntos/` | NT Kernel (scheduler, memory, I/O, object manager, registry) |
| `base/fs/` | Filesystems (NTFS, fsrec) |
| `drivers/` | Device drivers (network, storage, input, audio, USB) |
| `windows/core/` | User-mode kernel (NTUSER, window management) |
| `shell/` | Explorer, shell extensions, Control Panel |
| `ds/` | Directory Services (ADSI, LDAP, DNS, security) |
| `net/` | Networking (TCP/IP, DHCP, IPSec, NDIS) |
| `com/` | COM/OLE runtime, RPC |
| `inetcore/` | Internet components (MSHTML, WinInet, Outlook Express) |
| `inetsrv/` | Internet Services (IIS, MSMQ, POP3) |
| `termsrv/` | Terminal Services (RDP) |
| `admin/` | Admin tools (MMC, AD tools, Windows Installer) |
| `sdktools/` | 200+ SDK/build utilities |

### Kernel Subsystems (base/ntos/)

- `ke/` - Kernel executive (scheduler, exceptions)
- `mm/` - Memory management
- `ob/` - Object manager
- `ps/` - Process/thread management
- `io/` - I/O subsystem
- `ex/` - Executive (sync primitives)
- `config/` - Registry implementation
- `rtl/` - Runtime library

### Build System Files

- `sources` - Per-directory compile specification (12K+ files)
- `makefile` - Build rules (11K+ files)
- `dirs` - Subdirectory traversal lists
- `project.mk` - Project-wide build settings

## Certificate Management

Test certificates expire yearly. To renew:
```bash
# In Git Bash
certutil/generate.sh
```
Then install the generated PFX and CER files from `srv03rtm.certs/tools/`.

## Timebomb

Edit `DAYS` variable in `tools\postbuildscripts\timebomb.cmd` (line 44).
Valid values: 0 (disabled), 5, 15, 30, 60, 90, 120, 150, 180, 240, 360, 444

## Output Locations

- `{drive}\binaries.x86fre\` - Free (production) build output
- `{drive}\binaries.x86chk\` - Checked (debug) build output
- `{drive}\{buildtag}_{sku}.iso` - Generated ISO files

## Git Workflow

### Commit Practices

- **Separate commits for each scope**: Each logically distinct change should be its own commit. For example, when creating multiple analysis documents, commit each one separately rather than bundling them together.

- **Descriptive commit messages**: Include:
  - Brief summary line (what changed)
  - Key technical details in the body
  - Reference to relevant CVEs, functions, or files when applicable

- **Atomic changes**: A commit should represent one complete, self-contained change. If you need to revert, you should be able to revert just that one thing.

### Branch Strategy

- `main` - Stable code
- `study` - Research and analysis work (vulnerability analysis, documentation)

## Security Vulnerability Analysis

This codebase contains several historically significant vulnerabilities (MS03-026, MS04-011, MS08-067). When analyzing known vulnerabilities:

### Lessons Learned

1. **Verify against actual exploit code**: Don't stop at the first plausible vulnerability. Cross-reference with:
   - Metasploit module source code
   - Exploit-DB technical details
   - Buffer sizes mentioned in exploits (e.g., MAX_PATH vs 1024 chars)
   - Actual RPC function names targeted

2. **Exploit titles can be misleading**: Vulnerability names don't always match the vulnerable function. Example: "DsRolerUpgradeDownlevelServer Overflow" (MS04-011) actually targets `DsRolerGetDatabaseFacts`.

3. **Multiple vulnerabilities may exist**: Finding vulnerable code doesn't mean you found THE vulnerability. The codebase may have several overflow points - only one was weaponized.

4. **ASSERT() provides zero production protection**: Debug-only checks like `ASSERT(len <= MAX)` are compiled out in Release builds. These are red flags, not safeguards.

5. **Trace the full RPC path**: For RPC vulnerabilities, trace from:
   - IDL interface definition (parameter types, endpoints)
   - RPC dispatcher function (input validation)
   - Internal implementation (actual buffer operations)

6. **Cross-check should ask the right question**: When verifying analysis, ask "find the vulnerability" independently rather than "verify my analysis" - avoids confirmation bias.

### Vulnerability Analysis Document Requirements

Each vulnerability analysis document MUST include:

1. **Executive Summary**: CVE, bulletin, severity, affected service, attack vector

2. **Educational Overview** (REQUIRED): A detailed section explaining the vulnerability for students learning computer security, as if giving a high school CS lecture. Must include:
   - Simple analogies and real-world comparisons
   - ASCII diagrams illustrating concepts
   - Step-by-step explanation of how the vulnerability works
   - Comparison with other vulnerabilities (if applicable)
   - Key lessons for programmers
   - Glossary of technical terms

3. **Technical Analysis**:
   - Vulnerable function location and code excerpts
   - Attack vector and RPC entry points
   - Buffer layouts and memory diagrams
   - Exploitation details

4. **Historical Context**: Worm/exploit impact, timeline, real-world consequences

5. **Remediation**: How the vulnerability was fixed, modern defenses

### Vulnerability Documentation

Detailed analyses are in:
- `MS03-026-claude.md` - Blaster worm (DCOM RPC)
- `MS04-011-claude.md` - Sasser worm (LSASS)
- `MS08-067-claude.md` - Conficker worm (Server Service)
