# FileOpRace

Build x64 with CMake:

```
cmake -S . -B build
cmake --build build --config Release
```

```
FileOpRace.exe stamp <file>
FileOpRace.exe trial <new-junction> <bait-file> <canary-file> [--timeout ms] [--hold ms] [--demo]
```

Run `trial` on a local NTFS volume with two regular files of the same name in separate directories and a junction path that does not exist. It points the junction at the bait, arms an oplock, then switches the junction to the canary when the first open breaks the oplock. Start the process under test after `armed` appears. The junction is removed on normal exit or Ctrl+C.

`--demo` runs two local opens through the junction and records their file IDs. For a separate process, the output records the switch and any file content changes; it does not identify which process made a change or prove a read occurred.
