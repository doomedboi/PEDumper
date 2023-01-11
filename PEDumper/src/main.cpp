#include "dumper/Dumper.h"
#include <iostream>

int main()
{
    std::cout << "Enter file path: ";
    std::string path{};
    std::getline(std::cin, path);

    // make wrapper [load via file mapping, load as plain image]
    auto res = pe::LoadPE(path);
    if (res == false) {
        std::cout << "Error opening file!\n";
        return -1;
    }

    pe::ParsePE();
    
    return 0;
}