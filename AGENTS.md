# Repository Guidelines

## Project Structure & Module Organization
- Root is the Windows Server 2003/XP build tree; keep the checkout path as `.../srv03rtm`.
- `base/` core kernel and system libraries; `drivers/` device drivers; `com/`, `ds/`, `inetcore/`, `inetsrv/` platform stacks; `admin/` management tools; `sdktools/` SDK utilities; `tools/` build infrastructure and certificates.
- `project.mk` and `makefil0` define the top-level build; components follow the standard `dirs`/`sources`/`makefile` layout. Build outputs land in `binaries.<arch><type>` once the environment is initialized.

## Build, Test, and Development Commands
- Start a razzle shell from repo root: `tools/razzle64.cmd free offline` (or `tools/razzle.cmd` for x86). Run in an elevated prompt.
- Clean full build: `build /cZP -M 4` (alias `bcz`; `-M 4` avoids concurrency issues). Incremental: `build /ZP` (`bz`). Component-only: `cd base\ntos && bcz` (apply to any component dir).
- Postbuild packaging/validation: `tools/postbuild.cmd [-sku:{srv|sbs|ads|dtc|bla}]` after populating missing files via `tools/missing.cmd` or the `win2003_x86-missing-binaries` pack.
- ISO creation: `tools/oscdimg.cmd srv [dest.iso]` for the chosen SKU; outputs to the build drive with the build tag.
- Certificates: regenerate with `certutils/generate.sh` (Git Bash), then import the PFX/CER files from `srv03rtm.certs/tools` before building.

## Coding Style & Naming Conventions
- Preserve the existing style per file: 4-space indentation, CRLF line endings, uppercase macros, PascalCase APIs, `g_` for globals, `c_` for counts, and module-specific prefixes.
- Avoid modern C/C++ extensions unless already present; keep headers, precompiled headers, and resource identifiers consistent with neighboring files.
- Keep filenames and resources aligned with their directory/module (e.g., `base\ntos`, `inetcore\urlmon`) and reuse existing registry/resource IDs.

## Testing Guidelines
- No unified automated test runner; correctness is validated via successful builds and postbuild checks.
- For any change, rebuild the touched component and run `tools/postbuild.cmd` for affected SKUs; review `binaries.*\build_logs\postbuild.err` for regressions.
- When possible, boot or install an ISO produced by `oscdimg` to validate runtime behavior; note SKU-specific observations.

## Commit & Pull Request Guidelines
- Commit messages: short imperative subject (≤72 chars) mentioning the module, e.g., `Fix wininet cache quota clamp`; add a brief body for rationale and risks.
- Before proposing changes, list the build commands executed, postbuild status, SKUs exercised, and any ISO/boot results.
- Keep diffs focused, match existing formatting, and avoid committing generated binaries, certificates, or log artifacts.
