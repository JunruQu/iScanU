#include "ScannerManagerMC.h"
#include "ArchProperties.h"
#include "ArchFunctions.h"
#include "Handlers.h"
#include "Utility.h"
#include <signal.h>
 #include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <assert.h>
#include <errno.h>
#include <string>
#include <string.h>
#include <sched.h>
#include <fcntl.h>

//scanner manager for memcage method
ScannerManagerMC::ScannerManagerMC(int _numThreads, uint64_t first, uint64_t last) : ScannerManager(_numThreads) {

    registerHandlers();
    createCriticalOutputDir();
    setAltStack(altStack);
    initStdPage();

    checkForHang = true;
    managerFD = openCriticalOutputFile("results/manager");
    performanceLogFD = openCriticalOutputFile("results/performance");
    performanceLogSlowFactor = 10; //once every 10 alarms
    performanceLogCount = 0;
    if (last - first < (uint64_t)numThreads && last - first > 0) {
        numThreads = last - first;
    }
    uint64_t instrPerThread = (last - first) / numThreads;
    reg_t startInstruction = first;
    reg_t finalInstruction = first + instrPerThread;
    
    //Setup all scanner units
    for (int i = 0; i < numThreads; ++i) {
        Scanner* scannerData = (Scanner*)mmap(NULL, sizeof(Scanner), PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS | MAP_NORESERVE, 0, 0);
        scannerData->currentInstruction = startInstruction;
        scannerData->finalInstruction = finalInstruction;
        scannerData->outputFD = openCriticalOutputFile("results/thread" + std::to_string(i));
        scannerData->hangOutputFD = openCriticalOutputFile("results/hangs" + std::to_string(i));
        scannerData->debugFD = openCriticalOutputFile("results/debug" + std::to_string(i));
        localScannerInit(scannerData);

        pid_t pid = fork();
        if(pid == -1) {
            printf("Failed to create ptrace scanner\n");
            printf("%s\n", strerror(errno));
            exit(-1);
        }
        if(pid == 0) {
            initScanner(scannerData);
            exit(-1); //should never reach this point
        }
        threadDataMap.insert({pid, scannerData});
        scannerData->workerID = i;

        startInstruction = (finalInstruction + 1);
        finalInstruction += instrPerThread;
        if (i == numThreads - 1) {
            scannerData->finalInstruction = last;
        }
    }
}


ScannerManagerMC::~ScannerManagerMC() {

}

//initiate Scanner* data, assign initial values
void ScannerManagerMC::localScannerInit(Scanner* data) {
    data->oldNumInstrExec = 0;
    data->numInstrExec = 0;
    data->lastPerformanceExec = 0;
    data->isReady = false;
    data->isStopped = false;
    data->managerID = getpid();
    data->sizeError = false;
    data->currentInstructionSize = instructionSize;
}

//begin to run scanner
void ScannerManagerMC::runScanners() {

    bool allReady = false;
    //check all threads in threadDataMap, if thread.second->isReady = true
    //if all isReady = true, allReady = true
    while(!allReady) {
        allReady = true;
        
        for(const auto& thread : threadDataMap) {
            if(!thread.second->isReady) {
                allReady = false;
                break;
            }
        }
    }

    //send SIGUSR1 to all threads in threadDataMap
    for(const auto& thread : threadDataMap) {
        kill(thread.first, SIGUSR1);
    }

    //generate SIGALRM after 1 second
    alarm(1);
}

//initiate standard page
void ScannerManagerMC::initStdPage() {
    stdPage = (uint8_t*) malloc(pageSize);
    assert(pageSize % fillerInstructionSize == 0);
    for (uint8_t* i = stdPage; i < stdPage + pageSize; i += fillerInstructionSize) {
        memcpy(i, &fillerInstruction, fillerInstructionSize);
    }
}

//register handlers for SIG generated
void ScannerManagerMC::registerHandlers() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sigemptyset(&sa.sa_mask);

    //whatever SIG, execute function faultHandler()
    sa.sa_sigaction = faultHandler;
    sa.sa_flags   = SA_SIGINFO | SA_ONSTACK;
    for (int i = 1; i < 32; ++i) {
        sigaction(i, &sa, NULL);
    }
    //if get SIGALRM, execute function alarmHandler()
	sa.sa_sigaction = alarmHandler;
	sigaction(SIGALRM, &sa, NULL);
    
    //if get SIGUSR1, execute function entryHandler()
    sa.sa_sigaction = entryHandler;
	sigaction(SIGUSR1, &sa, NULL);

    //if get SIGUSR2, execute function hangHandler()
    sa.sa_sigaction = hangHandler;
	sigaction(SIGUSR2, &sa, NULL);
}
