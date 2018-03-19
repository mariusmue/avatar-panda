#include "panda/plugin.h"

#include "panda/tcg-llvm.h"
#include <llvm/PassManager.h>
#include <llvm/PassRegistry.h>
#include <llvm/Analysis/Verifier.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
//#include "llvm_taint_lib.h"


extern "C" {
    //TCGLLVMContext *tcg_llvm_ctx;
    bool init_plugin(void *self);
    void uninit_plugin(void *self);
}

//llvm::FunctionPassManager *FPM = nullptr;

bool insn_translate(CPUState *cpu, target_ulong pc){
    //printf("insn translate:\n");
    //printf("\t\tpc: %x\n", pc);
    return true;
}

int insn_exec(CPUState *cpu, target_ulong pc){
    //printf("insn exec:\n");
    printf("\t\tpc: %x\n", pc);
    return 0;
}


bool init_plugin(void *self){
    printf("[get_insn_trace] init_plugin\n");

    panda_cb pcb;     

    pcb.after_block_exec = insn_translate;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);

    pcb.after_block_exec = insn_exec;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);

    return true;
}


void uninit_plugin(void *self){
    printf("[get_insn_trace] uninit_plugin\n");
}

/*
panda_enable_llvm();
panda_enable_llvm_helpers();
llvm::FunctionPassManager *fpm = tcg_llvm_ctx->getFunctionPassManager();
fpm->add(new MyFunctionPass());
FPM->doInitialization();
*/
