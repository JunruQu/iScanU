#include "Handlers.h"
#include "Blacklist.h"
#include "ArchProperties.h"
#include "Scanner.h"
#include "ScannerManager.h"
#include "Utility.h"
#include "Analyser.h"
#include "Feeder.h"
#include "string.h"
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include "ArchFunctions.h"
#include <string>

//Memory cage handlers
//==============================================================================

void faultHandler(int signo, siginfo_t* info, void* context) {
//execute main scanning loop in the memcage method

    recoverState();
    //assign value to Scanner* data
    data->lastSigno = signo;
    data->lastInfo = info;
    data->lastContext = context;

    //execute function basicAnalysis() or insnAnalysis()
    (*analyse)(data);

    //execute function exhausive(), fetch nextInstruction
    //number of executed instruction + 1
    //if finished, end running
    instr_t nextInstruction;
    bool finished = (*fetchInstruction)(data, &nextInstruction);
    data->numInstrExec++;
    if (finished) {
        stopWorker(data);
    }

    //if max pc relative write offset != 0, then write standard page to instruction page
    if(maxPcRelativeWriteOffset) {
        writeStdPage(data->instructionPage);
    }

    //write nextInstruction to address of instruction pointer
    //assign nextInstrution to current instruction
    writeInstruction(data->instructionPointer, nextInstruction);
    data->currentInstruction = nextInstruction;

    //reset context
    ucontext_t* ucontext = (ucontext_t*)context;
    setState(&ucontext->uc_mcontext, (reg_t)data->instructionPointer, NULL);
    clearCache(data->instructionPage, data->instructionPage + pageSize);
}


void alarmHandler(int signo, siginfo_t* info, void* context) {
//log performance, check for hangs
    
    //generate SIGALRM now(after 0 second)
	alarm(0);
    //log some performance metrics
    if(performanceLogCount == performanceLogSlowFactor - 1) {
        int insn = 0;
        int temp;
        std::string output = "===== start of performance log =====\n";
        for(auto& thread : threadDataMap) {
            if(thread.second->isStopped) continue;
            temp = thread.second->numInstrExec - thread.second->lastPerformanceExec;
            insn += temp;
            output += "thread " + std::to_string((uint64_t)thread.second->workerID) + ": " + std::to_string(temp) + "\n";
            thread.second->lastPerformanceExec = thread.second->numInstrExec;
        }
        output += "Total: " + std::to_string(insn) + "\n";
        write(performanceLogFD, output.c_str(), output.size());
        writeTimestamp(performanceLogFD);
    }
    performanceLogCount++;
    performanceLogCount %= performanceLogSlowFactor;


    //check for hang condition and fix if occured & check for completion
    //traverse threadDataMap in type thread
    //thread is a pair, first member is type pid_t, second member is type Scanner
    bool finished = true;
    for(auto& thread : threadDataMap) {
        if(!thread.second->isStopped) {
            finished = false;
        }

        //assign numInstExec to currentExecuted
        //assign oldNumInstExec oldExecuted
        uint64_t currentExecuted = thread.second->numInstrExec;
        uint64_t oldExecuted = thread.second->oldNumInstrExec;

        //if thread is not stopped, and executed number of instructions doesn't change
        //then send SIGUSR2 to this thread
        if(checkForHang && currentExecuted == oldExecuted && !thread.second->isStopped) {
            kill(thread.first, SIGUSR2);
        }

        //refresh oldNumInstrExec
        thread.second->oldNumInstrExec = currentExecuted;
    }
    if(finished) {
        std::string output = "finished run\n";
        write(managerFD, output.c_str(), output.size());
        exit(0);
    }
    //generate SIGALRM after 1 second
	alarm(1);
}


void entryHandler(int signo, siginfo_t* info, void* context) {
//store good state for faultHandler and alarmHandler

    setRecoveryData(data);
    writeTimestamp(data->outputFD);
    std::string start = "======= start of run =======\n";
    write(data->outputFD, start.c_str(), start.size());
    
    //fetch currentInstruction
    //if current instruction is in blacklist
    //find next instruction not in blacklist and assign it to currentInstruction
    //if finished, end running
    if (blacklist.search(data->currentInstruction)) {
    	bool finished = (*fetchInstruction)(data, &data->currentInstruction);
    	if (finished) {
            stopWorker(data);
    	}
    }

    //write current istruction to address of instruction pointer
    writeInstruction(data->instructionPointer, data->currentInstruction);

    //reset context
    ucontext_t* ucontext = (ucontext_t*)context;
    setState(&ucontext->uc_mcontext, (reg_t)data->instructionPointer, NULL);
    clearCache(data->instructionPage, data->instructionPage + pageSize);
}

void hangHandler(int signo, siginfo_t* info, void* context) {
//executed when scanner gets stuck, force to move to next instruction

    recoverState();
    std::string output = "HANG " + std::to_string(data->currentInstruction) + "\n";
    write(data->hangOutputFD, output.c_str(), output.size());
    data->lastSigno = SIGSEGV;
    data->lastInfo = info;
    data->lastContext = context;
    //execute function basicAnalysis()
    (*analyse)(data);
    
    //write standard page to instruction page
    memcpy(data->instructionPage, stdPage, pageSize);

    //fetch currentInstruction
    //if finished, end running
	bool finished = (*fetchInstruction)(data, &data->currentInstruction);
    if(finished) {
        stopWorker(data);
    }
    
    //write current instruction to address of instruction pointer
	writeInstruction(data->instructionPointer, data->currentInstruction);
    
    //reset context
	ucontext_t* ucontext = (ucontext_t*)context;
    setState(&ucontext->uc_mcontext, (reg_t)data->instructionPointer, NULL);
    clearCache(data->instructionPage, data->instructionPage + pageSize);
}

//==============================================================================
//Ptrace Handlers

void startHandlerPtrace(int signo, siginfo_t* info, void* context) {

}

void hangHandlerPtrace(int signo, siginfo_t* info, void* context) {
    std::string output = "HANG " + std::to_string(data->currentInstruction) + "\n";
    write(data->hangOutputFD, output.c_str(), output.size());
    data->lastSigno = SIGSEGV;
    data->lastInfo = info;
    data->lastContext = context;
    (*analyse)(data);

	bool finished = (*fetchInstruction)(data, &data->currentInstruction);
    if(finished) {
        printf("stopping from hang\n");
        stopWorker(data);
    }
	writeInstruction(data->instructionPointer, data->currentInstruction);

	ucontext_t* ucontext = (ucontext_t*)context;
    setState(&ucontext->uc_mcontext, (reg_t)data->instructionPointer, NULL);
    clearCache(data->instructionPage, data->instructionPage + pageSize);
}
