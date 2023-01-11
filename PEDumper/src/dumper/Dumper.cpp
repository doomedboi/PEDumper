#include "Dumper.h"

bool pe::LoadAsMapping(std::string_view path)
{
    if (TRUE != std::filesystem::exists(path))
        return false;
    
    auto validateHandle = [](HANDLE handle)
    {
        return handle != INVALID_HANDLE_VALUE;
    };

    HANDLE hFile = NULL;
    
    if (TRUE)
    {
        hFile =  ::CreateFileA(path.data(), FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, 0, NULL);

        if (TRUE != validateHandle(hFile))
            return false;

        auto hFileMap = ::CreateFileMappingA(hFile, NULL,
            SEC_IMAGE | PAGE_READONLY, 0, 0, NULL);

        if (TRUE != validateHandle(hFileMap)) {
            CloseHandle(hFile);
            return false;
        }

        mapOfFile = ::MapViewOfFile(hFileMap, FILE_MAP_READ, NULL, NULL, NULL);
        if (nullptr == mapOfFile) 
            return false;
        
        CloseHandle(hFile);
        CloseHandle(hFileMap);
        return true;
    }
    
    return false;
}

bool pe::ParsePE()
{
    PIMAGE_DOS_HEADER dosHeader = ParseDOS();
    if (nullptr == dosHeader)
    {
        std::cout << "Can't parse dos headers!\n";
        return false;
    }
    
    auto peNtHeaders = ParseHeaders();

    if (isx64 == pe::Arch::x32)
    {
        if (false == std::holds_alternative<PIMAGE_NT_HEADERS32>(peNtHeaders)
            && false == std::holds_alternative<PIMAGE_NT_HEADERS64>(peNtHeaders))
        {
            std::cout << "Can't parse Nt headers!\n";
            return false;
        }
    }
    
    auto parseSections = [](auto peNtHeaders)
    {
        
        auto numOfSections = peNtHeaders->FileHeader.NumberOfSections;
        std::vector<PIMAGE_SECTION_HEADER> sections; sections.reserve(numOfSections);
        
        auto firstSection = reinterpret_cast<PIMAGE_SECTION_HEADER>
            (peNtHeaders + 1);

        for (int i = 0; i < numOfSections; ++i)
            sections.emplace_back(firstSection + i);

        return sections; // pray for always RVA in cxx17
    };
    
    isx64 == pe::Arch::x64 ? parseSections(std::get< PIMAGE_NT_HEADERS64>(peNtHeaders))
        : parseSections(std::get<PIMAGE_NT_HEADERS32>(peNtHeaders));
    ParseImport();
    ParseExport();
    ParseRelocs();
    
    

    return true;
}

PIMAGE_DATA_DIRECTORY pe::ParseDataDir()
{
    auto ntHeaders = ParseHeaders();
    if (std::holds_alternative<PIMAGE_NT_HEADERS32>(ntHeaders))
        return std::get<PIMAGE_NT_HEADERS32>(ntHeaders)->OptionalHeader.DataDirectory;
    else
        return std::get<PIMAGE_NT_HEADERS64>(ntHeaders)->OptionalHeader.DataDirectory;
}

void pe::ParseImport()
{
    auto DataDir = ParseDataDir();
    auto importTable = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR> // Import Dir Table 
        ((PBYTE)mapOfFile + DataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (nullptr == importTable)
        return;

    DWORD iat = 0;

    auto addrOfData = [](auto addr)
    {
        return isx64 == Arch::x64? ((PIMAGE_THUNK_DATA64)addr)->u1.AddressOfData :
            ((PIMAGE_THUNK_DATA32)addr)->u1.AddressOfData;
    };

    // lookup table has either name or ordinal
    while (importTable->Characteristics != NULL) // it represents one dll (inside operator's body)
    {
        ::printf("[+]DLL's name: %s\n", (char*)(RvaToVa(importTable->Name)));
        
        iat = (DWORD)(RvaToVa(importTable->OriginalFirstThunk));
        
        while (addrOfData(iat))
        {
            auto addr = addrOfData(iat); // it's thunk_data now
            auto addrOfName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(addr);
            
            if (addrOfName->Name)
                ::printf(" |\n  -[+]%s\n", (char*)(RvaToVa((DWORD)(addrOfName->Name))));

            iat += 4;
        }

        importTable = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>
            ((PBYTE)importTable + sizeof(IMAGE_IMPORT_DESCRIPTOR));
    }

}

std::variant<PIMAGE_NT_HEADERS32, PIMAGE_NT_HEADERS64> pe::ParseHeaders()
{
    auto dos = ParseDOS();
    auto peNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS32>((PBYTE)dos + dos->e_lfanew);
    if (peNtHeaders->OptionalHeader.Magic == 0x20B)
        isx64 = Arch::x64;

    if (isx64 == Arch::x32)
        return peNtHeaders;
    else return reinterpret_cast<PIMAGE_NT_HEADERS64>((PBYTE)dos + dos->e_lfanew);
}

bool pe::LoadPE(std::string_view path)
{
    auto status = pe::LoadAsMapping(path);
    if (status != TRUE)
        status = pe::LoadAsPlainBytes(path);

    return status;
}

PIMAGE_DOS_HEADER pe::ParseDOS()
{
    // we need to check a ViewOf file or plain pe
    return reinterpret_cast<PIMAGE_DOS_HEADER>(mapOfFile);
}

void pe::ParseRelocs()
{
    auto dataDir = ParseDataDir();
    auto vaRelocs = RvaToVa(dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    
    
    while (PIMAGE_BASE_RELOCATION(vaRelocs)->SizeOfBlock)
    {
        auto currentBlock = PIMAGE_BASE_RELOCATION(vaRelocs);
        auto page = currentBlock->VirtualAddress;
        PDWORD pdwEntries = (PDWORD)(currentBlock) + 2;
        auto countOfEntries = (currentBlock->SizeOfBlock - sizeof(currentBlock) - sizeof(currentBlock->VirtualAddress))
            / sizeof(WORD);
        
        for (int i = 0; i < countOfEntries; ++i)
        {
            auto type = *(PWORD)((PWORD)pdwEntries + i) >> 12;
            auto offset = *(PWORD)((PWORD)pdwEntries + i) & ((1 << 12)-1); //from page

            std::cout << std::hex << page + offset << std::endl;
        }

        vaRelocs += currentBlock->SizeOfBlock;
    }

}


void pe::ParseExport()
{
    auto dataDir = ParseDataDir();
    auto exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>
        (RvaToVa(dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
    
    auto ordinalTable  = (PWORD)(exportDir->AddressOfNameOrdinals + (PBYTE)mapOfFile);
    auto funcsRvaTable = (PDWORD)(exportDir->AddressOfFunctions + (PBYTE)mapOfFile);
    auto names         = (PDWORD)(exportDir->AddressOfNames + (PBYTE)mapOfFile);
    
    auto countOfEntries = std::max<>(exportDir->NumberOfNames, exportDir->NumberOfFunctions);
    for (int i = 0; i < countOfEntries; ++i)
    {        
            
        std::string name{};
        if (i < exportDir->NumberOfNames)
        {
            name = (char*)(names[i] + (PBYTE)mapOfFile);
            if (!name.c_str())
                continue;
        }
        else
            name = "";
        auto indexInAddresses = ordinalTable[i];

        auto rvaFunc = funcsRvaTable[indexInAddresses];        
        if (!rvaFunc)
            continue;
        std::cout << name << " addr: " << std::hex << rvaFunc << std::endl;

    }
}

bool pe::LoadAsPlainBytes(std::string_view path)
{
    FILE* file = nullptr;
    
    ::fopen_s(&file, path.data(), "rb");
    if (nullptr != file)
    {
        fseek(file, 0L, SEEK_END);
        DWORD dwFileSize = ftell(file);
        fseek(file, 0L, SEEK_SET);

        plainPE.reserve(dwFileSize);

        fread(plainPE.data(), 1, plainPE.size(), file);
        fclose(file);
        return true;
    }
    return false;
}
               