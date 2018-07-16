/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include "panda/tcg-llvm.h"

#include <capstone/capstone.h>

#include "FPSkel.h"
#include <llvm/PassManager.h>
#include <llvm/PassRegistry.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Bitcode/ReaderWriter.h>
#include <llvm/IR/Function.h>

#if defined(TARGET_ARM)
#include <capstone/arm.h>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
}

extern "C" TCGLLVMContext *tcg_llvm_ctx;

int bb_insn_count = 0;
csh handle;
size_t count;

std::deque<ins> insn_queue;

int before_block_exec(CPUState *cpu, TranslationBlock *tb){
    static uint64_t bb_count = 0;
    bb_insn_count = 0;

    printf("===========before_block_exec - size: %x, icount: %x, pc: %x ============\n", tb->size, tb->icount, tb->pc);

    bb_count++;

    if (tb->llvm_tc_ptr) {
        auto FP = new llvm::FPSkel(&insn_queue);
        FP->runOnFunction(*tb->llvm_function);
    }

    return 0;
}

bool insn_translate(CPUState *cpu, target_ulong pc){
    printf("\ninsn translate:");

    long unsigned int size = 4;
    unsigned char *buf = (unsigned char *) malloc(size);

    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    int err = panda_virtual_memory_rw(ENV_GET_CPU(env), pc, buf, size, 0);
    if (err == -1) printf("Couldn't read TB memory!\n");

    cs_insn *insn;
    count = cs_disasm(handle, buf, size, pc, 0, &insn);

    if (count > 0) {
        unsigned int ins_buf = *reinterpret_cast<unsigned int* >(buf);
        insn_queue.emplace_back(pc, ins_buf);

        size_t j;
        for (j = 0; j < count; j++) {
            printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
        }
        cs_free(insn, count);
    } else {
        printf("ERROR: Failed to disassemble given code!\n");
    }

    free(buf);

    return true;
}

bool init_plugin(void *self) {

    printf("[map_insn] init_plugin\n");

    panda_cb pcb;     

    panda_enable_precise_pc();

    if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle) != CS_ERR_OK)
        return false;

    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    pcb.insn_translate = insn_translate;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);

    if (!execute_llvm){
        panda_enable_llvm();
    }

    // not there when --llvm option is passed!
    if (tcg_llvm_ctx) {
        panda_enable_llvm_helpers();
        llvm::FunctionPassManager *FPM = tcg_llvm_ctx->getFunctionPassManager();
        if (FPM) {
            FPM->add(new llvm::FPSkel(&insn_queue));
            FPM->doInitialization();
        }
    }

    return true;
}

void uninit_plugin(void *self){
    printf("[map_insn] uninit_plugin\n");

    tcg_llvm_write_module(tcg_llvm_ctx, "dumped_bitcode.bc"); 

    panda_disable_llvm_helpers();

    if (execute_llvm){
        panda_disable_llvm();
    }
}

#endif // TARGET_ARM
