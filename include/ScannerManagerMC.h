#pragma once

#include "ScannerManager.h"

//this is a derived class from class ScannerManager
class ScannerManagerMC : public ScannerManager {
public:
    //this is a constructor
    ScannerManagerMC(int numThreads, uint64_t first, uint64_t last);

    //this is a destructor
    ~ScannerManagerMC();
    
    void runScanners();
private:
    stack_t altStack;
    
    void initStdPage();
    void registerHandlers();
    void localScannerInit(Scanner* data);
};
