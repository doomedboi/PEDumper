#pragma once


#include "../common/winHeaders.h"
#include <cstdio>
#include <filesystem>
#include <vector>
#include <variant>
#include <string>
#include <iostream>

namespace pe
{
    static bool LoadAsMapping(std::string_view path);

    bool ParsePE();

    PIMAGE_DATA_DIRECTORY ParseDataDir();

    void ParseImport();    
    
    std::variant<PIMAGE_NT_HEADERS32, PIMAGE_NT_HEADERS64>
        ParseHeaders();

    bool LoadPE(std::string_view path);

    PIMAGE_DOS_HEADER ParseDOS();

    enum class Arch {
        x32 = 0,
        x64
    };    

    inline LPVOID mapOfFile = nullptr;
    inline std::vector<BYTE> plainPE{};
    inline Arch isx64 = Arch::x32;
    union _peNtHeaders 
    {
       PIMAGE_NT_HEADERS32 x32;
       PIMAGE_NT_HEADERS64 x64;
    };

    // takes image view from map
    template <typename addr>
    addr RvaToVa(addr rva)
    {
        return (addr)(rva + (PBYTE)mapOfFile);
    }

    void ParseRelocs();

    // w/o export by ordinal
    void ParseExport();

    static bool LoadAsPlainBytes(std::string_view path);

}