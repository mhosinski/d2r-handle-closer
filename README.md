# D2R Handle Closer

A lightweight Windows tray application that automatically detects running instances of **Diablo II Resurrected (D2R.exe)** and closes a specific event handle used by the game to prevent multiple instances:

`\Sessions\1\BaseNamedObjects\DiabloII Check For Other Instances`

This makes it possible to run multiple copies of D2R on the same machine.

---

## ⚠️ Disclaimer

* This tool uses **undocumented Windows APIs** (`NtQuerySystemInformation`, `NtQueryObject`) to enumerate and close handles.
* Running this against a game process may **violate the game’s Terms of Service** and could trigger **anti-cheat protections**.
* Use entirely at your **own risk**. The author assumes no responsibility for bans, crashes, or other consequences.

---

## Features

* Runs as a **tray application** with a context menu:

  * Start/Stop monitoring
  * Exit
* Periodically scans every 3 seconds for `D2R.exe`.
* Closes the named event handle if found.
* Shows a Windows notification when a handle is closed.

---

## Requirements

* Windows 10 or 11 (x64).
* [.NET 8.0 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/8.0) or later.
* Administrator privileges (required to enumerate system handles).

---

## Building

1. Clone the repo

   git clone [https://github.com/yourname/d2r-handle-closer.git](https://github.com/yourname/d2r-handle-closer.git)
   cd d2r-handle-closer

2. Build in Release mode (x64)

   dotnet build -c Release -p:Platform=x64

3. Run the executable

   .\bin\Release\net8.0-windows\D2RHandleCloser.exe

(If you didn’t embed an admin manifest, right-click the EXE → “Run as administrator”.)

---

## Publishing a Single EXE

You can publish a self-contained single file:

```
dotnet publish -c Release -r win-x64 ^
  -p:PublishSingleFile=true ^
  -p:PublishTrimmed=false ^
  -p:IncludeNativeLibrariesForSelfExtract=true
```

Result:

```
bin\Release\net8.0-windows\win-x64\publish\D2RHandleCloser.exe
```

---

## Startup on Login (Optional)

* **Quick way:** Place a shortcut to the EXE in `shell:startup`.
* **Cleaner way:** Create a Task Scheduler entry:

  * Trigger: “At log on”
  * Action: Start program → `D2RHandleCloser.exe`
  * Check “Run with highest privileges”

---

## Development Notes

* Uses `System.Windows.Forms.NotifyIcon` for the tray icon.
* Uses P/Invoke to call `NtQuerySystemInformation`, `NtQueryObject`, and `DuplicateHandle`.
* Must be built as **x64** (the handle table structs are 64-bit layouts).
* No `unsafe` blocks are required; pointer math is avoided via `IntPtr.Add`.

---

## License

MIT License. See `LICENSE` for details.
