# fixture: provenance-iwr-outfile-unverified

Sibling of `provenance-bare-wget-unverified` for PowerShell's
`Invoke-WebRequest -OutFile` (`windows-build.yml:msvc` uses it). A Windows
runner unpacking an unverified tarball is the same privilege boundary as a
Linux one; the pre-fix scoping regex knew only `wget`/`curl`, so every
PowerShell download job was invisible to this check.

`provenance` must go red here.

Workflow: `.github/workflows/ci.yml`.
