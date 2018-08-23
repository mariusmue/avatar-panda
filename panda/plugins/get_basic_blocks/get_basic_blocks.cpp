#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <map>
#include <list>
#include <algorithm>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>
#include <vector>
#include <iostream>
#include <sstream>

extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int before_block_exec(CPUState *env, TranslationBlock *tb);
}

int basic_blocks_bin;

int before_block_exec(CPUState *env, TranslationBlock *tb) {
    printf("pc: %d\n", tb->pc);

    if (write(serial_basic_blocks_bin, &tb->pc, 4) != 4){
        fprintf(stderr, "Couldn't write pc\n");
        perror("write");
    }

    return 0;
}

bool init_plugin(void *self) {
    printf("Initializing plugin get_basic_blocks\n");

    basic_blocks_bin = open("basic_blocks.bin", O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
    if(basic_blocks_bin == -1) {
        printf("Cannor open/create basic_blocks.bin:\n");
        perror("fopen");
        return false;
    }

    panda_cb pcb;
    panda_enable_memcb();
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    return true;
}

void uninit_plugin(void *self) {
    printf("Uninitializing plugin\n");

    close(basic_blocks_bin);

    panda_disable_memcb();
}
