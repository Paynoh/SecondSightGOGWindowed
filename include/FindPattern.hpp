#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>

class PatternScanner {
public:
    
    PatternScanner() : module_base_(0), module_size_(0), address_(0) {}

    
    template <typename T>
    T as() const
    {
        return reinterpret_cast<T>(address_);
    }

    // Adds an offset to the found address
    PatternScanner& offset(ptrdiff_t offset)
    {
        address_ += offset;
        return *this;
    }

    // New FindPattern method to combine module and pattern search
    static PatternScanner FindPattern(const std::string& module_name, const char* pattern, const char* mask)
    {
        PatternScanner scanner;
        scanner.GetModuleInfo(module_name);
        scanner.address_ = scanner.Scan(pattern, mask);
        return scanner;
    }

    // Inside method is now redundant, so it can be removed.

private:
    uintptr_t module_base_;  // Base address of the module
    size_t module_size_;     // Size of the module
    uintptr_t address_;      // Address where the pattern is found

    // Method to get information about a module (EXE or DLL)
    void GetModuleInfo(const std::string& module_name)
    {
        HMODULE hModule = GetModuleHandleA(module_name.c_str());
        if (!hModule)
			return;
        MODULEENTRY32 module_entry = { sizeof(MODULEENTRY32) };
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
        if (snapshot == INVALID_HANDLE_VALUE)
            return;

        if (Module32First(snapshot, &module_entry))
        {
            do
            {
                if (std::string(module_entry.szModule) == module_name)
                {
                    module_base_ = reinterpret_cast<uintptr_t>(module_entry.modBaseAddr);
                    module_size_ = module_entry.modBaseSize;
                    break;
                }
            } while (Module32Next(snapshot, &module_entry));
        }

        CloseHandle(snapshot);
    }

    // Pattern scanning method
    uintptr_t Scan(const char* pattern, const char* mask)
    {
        size_t pattern_length = strlen(mask);

        for (size_t i = 0; i < module_size_ - pattern_length; ++i)
        {
            bool found = true;
            for (size_t j = 0; j < pattern_length; ++j)
            {
                if (mask[j] != '?' && pattern[j] != *reinterpret_cast<char*>(module_base_ + i + j))
                {
                    found = false;
                    break;
                }
            }

            if (found)
            {
                return module_base_ + i;
            }
        }
        return 0;
    }
};
