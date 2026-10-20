# ZIP validators: read before enabling

These guards are strict on purpose. They are meant for apps that accept plain documents, images and data inside zips. Check what your app accepts before you enable them.

| If your app accepts... | Avoid or relax these guards |
|---|---|
| Code / project submissions | DangerousExtensionGuard, ExecutableContentGuard |
| Software downloads, installers | DangerousExtensionGuard, ExecutableContentGuard |
| Game mods and plugins | DangerousExtensionGuard, ExecutableContentGuard |
| Admin / IT scripts | DangerousExtensionGuard, ExecutableContentGuard |
| Web projects (js, html) | DangerousExtensionGuard |
| Backups / zips inside zips | NestedArchiveGuard |
| Password-protected zips | EncryptedEntryGuard |

If you need one of these, remove that validator from your pipeline or relax it first (allow certain extensions or lower the severity).

All other zip guards (Zip Bomb, Zip Slip, Entry Count, Duplicate Entry, Symlink, Device Name, Unicode Control, Trailing Character, Nested Zip Inspector) are safe for any app.
