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

int trace_block_exec(CPUState *cpu, TranslationBlock *tb){
    printf("block exec:\n");
    printf("\t\ttb->pc: %x\n", tb->pc);
    printf("\t\ttb->cs_base: %x\n", tb->cs_base);
    printf("\t\ttb->flags: %x\n", tb->flags);
    printf("\t\ttb->llvm_tc_ptr: %x\n", tb->llvm_tc_ptr);
    printf("\t\ttb->llvm_tc_end: %x\n", tb->llvm_tc_end);
    return 0;
}


bool init_plugin(void *self){
    printf("[get_llvm_trace] init_plugin\n");

    panda_cb pcb;     

    panda_enable_llvm();
    panda_enable_llvm_helpers();

    pcb.after_block_exec = trace_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);

    return true;
}


void uninit_plugin(void *self){
    printf("[get_llvm_trace] uninit_plugin\n");
}

/*
panda_enable_llvm();
panda_enable_llvm_helpers();
llvm::FunctionPassManager *fpm = tcg_llvm_ctx->getFunctionPassManager();
fpm->add(new MyFunctionPass());
FPM->doInitialization();
*/
