//Contains general analysis stages that can be set in main.cpp

#include "Analyser.h"
#include "ArchFunctions.h"
#include <unistd.h>
#include <string>
#include <string.h>
#include <bitset>

void (*analyse)(Scanner*);

void basicAnalysis(Scanner* data) {
//get [signo info->si_code] value from Scanner* data
//get isValid value from function disassemble

    int signo = data->lastSigno;
    siginfo_t* info = data->lastInfo;
    void* context = data->lastContext;

    bool isValid = disassemble(data, data->currentInstruction, NULL);

    //Log instruction if it is a disassembler fault or hidden instruction
    //instruction is not recognized when SIGILL is delivered with si_code ILL_ILLOPC
	if(signo == SIGILL && info->si_code == ILL_ILLOPC && isValid) {
        std::string output = "D " + std::to_string(data->currentInstruction)+ " " + std::to_string(signo) + " " + std::to_string(info->si_code) + "\n";
        write(data->outputFD, output.c_str(), output.size());
	}
	else if(!(signo == SIGILL && info->si_code == ILL_ILLOPC) && !isValid) {
        std::string output = "H " + std::to_string(data->currentInstruction)+ " " + std::to_string(signo) + " " + std::to_string(info->si_code) + "\n";
        write(data->outputFD, output.c_str(), output.size());
	}
}

void insnAnalysis(Scanner* data) {
//same as basicAnalysis, only change output

    int signo = data->lastSigno;
    siginfo_t* info = data->lastInfo;
    void* context = data->lastContext;

    bool isValid = disassemble(data, data->currentInstruction, NULL);

    std::string output = std::to_string((uint64_t)data->currentInstruction)+ " " + std::to_string(signo) + " " + std::to_string((uint64_t)info->si_code) + "\n";
    write(data->outputFD, output.c_str(), output.size());
    output = "si_addr: " + std::to_string((uint64_t)info->si_addr) + ", si_value: " + std::to_string((uint64_t)info->si_value.sival_ptr) + ", ip: " + std::to_string((uint64_t)data->instructionPointer) + "\n";
    write(data->outputFD, output.c_str(), output.size());

    if(signo == SIGILL && info->si_code == ILL_ILLOPC && isValid) {
        output = "Disas fault\n";
        write(data->outputFD, output.c_str(), output.size());
    }
    else if((signo != SIGILL || info->si_code != ILL_ILLOPC) && !isValid) {
        output = "Hidden\n";
        write(data->outputFD, output.c_str(), output.size());
    }
}

void myAnalysis(Scanner* data) {
//get [signo info->si_code] value from Scanner* data
//get isValid value from function disassemble

    int signo = data->lastSigno;
    siginfo_t* info = data->lastInfo;
    void* context = data->lastContext;

    int tempInst=data->currentInstruction;

    bool isValid = disassemble(data, data->currentInstruction, NULL);

    std::bitset<32> bitInst(tempInst);

    //Log instruction if it is a disassembler fault or hidden instruction
    //instruction is not recognized when SIGILL is delivered with si_code ILL_ILLOPC
	if(signo == SIGILL && info->si_code == ILL_ILLOPC && isValid) {
        std::string output = "D " + bitInst.to_string();+ " " + std::to_string(signo) + " " + std::to_string(info->si_code) + "\n";
        write(data->outputFD, output.c_str(), output.size());
	}
	else if(!(signo == SIGILL && info->si_code == ILL_ILLOPC) && !isValid) {
        std::string output = "H " + bitInst.to_string();+ " " + std::to_string(signo) + " " + std::to_string(info->si_code) + "\n";
        write(data->outputFD, output.c_str(), output.size());
	}
}