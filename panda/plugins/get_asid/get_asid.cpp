#include "panda/plugin.h"

#include <stdlib.h>
#include "panda/plog-cc.hpp"

extern "C" {
bool init_plugin(void *self);
void uninit_plugin(void *self);
}

int after_block_exec(CPUState *cpu, TranslationBlock *tb){
    fprintf(stderr, "[after_block_exec] current_asid: %x\n", panda_current_asid(cpu));

    return 0;
}

bool init_plugin(void *self){
    printf("[get_asid] init_plugin\n");

    panda_cb pcb;     

    pcb.after_block_exec = after_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);

    return true;
}


void uninit_plugin(void *self){
    printf("[get_asid] uninit_plugin\n");
}


