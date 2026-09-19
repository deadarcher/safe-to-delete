# SafeToDelete

**What is actually safe to delete on Windows?** Run one script and get every reclaimable location graded by how safe it is to remove *and what it costs you*, including which part of the Windows Installer cache is orphaned and which part is still needed for repair and uninstall.

**Use it now (hosted):** https://getrff.com/safe-to-delete/

---

## Why another disk tool

Space analysers show you *where* the bytes are. Cleanup scripts just *delete*. Neither answers the question you actually have, which is what you can remove without creating a ticket for yourself in six weeks.

The Windows Installer cache (`C:\Windows\Installer`) is the clearest example. Most of it is still doing a job: delete the wrong part and you break repair and uninstall for software that's still installed, and nobody finds out until the next patch or removal fails with *"the feature you are trying to use is on a network resource that is unavailable"* and asks for an installer nobody kept. A script that empties the folder frees space today and hands you that ticket later. This one tells you which packages are orphaned and which have to stay.

## It reports by default

A plain run reads, reports, and writes one JSON file. That's the default, and there's no flag you have to remember to get it.

- `-Apply` removes the **safe** rows only.
- Rows with a stated cost need `-IncludeCaution` on top.
- Rows marked in-use can't be removed at all.
- It refuses to run while an install or a patch cycle is in progress.
- It never touches Documents, Desktop, Downloads, or anything OneDrive is syncing.

`SupportsShouldProcess` is on, so `-WhatIf` and `-Confirm` work, and `ConfirmImpact` is High: `-Apply` prompts unless you pass `-Confirm:$false`. Deleting from someone else's system drive should have to be asked for twice.

## If you do let it delete, there's a record

A plain-text log next to the JSON, one line per file with the full path and its size, plus a line for every file it couldn't remove and why. It appends, so each run adds to the history rather than erasing the last one. Six weeks later, when someone asks what happened to a file, that log is the answer and you read it in Notepad. Turn it off with `-NoRemovalLog`.

## Run it

From an **elevated** PowerShell prompt:

```powershell
powershell -ExecutionPolicy RemoteSigned -File .\safe-to-delete.ps1
```

Add `-Gui` for a window, or `-Quick` to skip the slow checks.

**`RemoteSigned`, not `Bypass`, on purpose.** This script is signed, and `RemoteSigned` is what makes Windows actually check that. Verify it yourself before running it:

```powershell
Get-AuthenticodeSignature .\safe-to-delete.ps1 | Format-List Status, SignerCertificate
```

`Valid`, signed by **Vitko Software, LLC**. Change one byte and it reads `HashMismatch`; strip the signature block and it reads `NotSigned`. Either way you'd know.

## A note on the file names

This tool was called **Disk Reclaim** until 2026-09-19. Renaming the script file doesn't affect its signature (Authenticode hashes the contents, not the filename), but the names *inside* it are frozen until it's re-signed. So it still writes `disk-reclaim.json` and `disk-reclaim-removed.log`, and `Get-Help` still shows the old filename in its examples. Same file, same place, on your Desktop.

## Nothing is uploaded

The script runs locally and writes locally. The hosted page at the link above analyses the JSON **in your browser**; the file never leaves your machine. You don't need the page at all, since the script prints its findings itself.

## Scope

This is a **single-machine, point-in-time** tool, deliberately. No history, no scheduling, no fleet.

If you want this continuously across a fleet, with the drift tracked and the cleanup deployed rather than run by hand, that's [RFF](https://getrff.com).

## License

MIT. See [LICENSE](LICENSE).
