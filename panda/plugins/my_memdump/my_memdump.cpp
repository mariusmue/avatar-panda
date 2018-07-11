// XXX: plugin ported to panda2, starting from https://github.com/panda-re/panda/blob/panda1/qemu/panda_plugins/memdump/memdump.cpp

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
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


// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size);
bool check_first_read(struct mem_access ma);
bool check_no_write(struct mem_access ma);
}


struct mem_access {
    target_ulong pc;
    target_ulong addr;
    target_ulong size;
    uint8_t *buf;
};

using namespace std;
vector<struct mem_access> good_reads;
vector<struct mem_access> writes;


int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    struct mem_access ma;

    // populate the struct
    ma.pc = pc;
    ma.addr = addr;
    ma.size = size;
    ma.buf = (uint8_t *) malloc(size*sizeof(uint8_t));
    memcpy(ma.buf, buf, size);

    fprintf(stderr, "[mem_write] - pc: %x, addr: %x, size: %x, ", pc, addr, size);
    for (int i=0; i<size; i++){
        fprintf(stderr, "0x%hhx ", ma.buf[i]);
    }
    fprintf(stderr, "\n");

    writes.push_back(ma);

    return 1;
}

void error(std::string message){
    cerr << "=================================================\n";
    cerr << "   [my_memdump] - ERROR: " << message << endl;
    cerr << "=================================================\n";
    exit(1);
}


// TODO: the following two functions can be squeezed into one, 
// I'm just not sure at the moment whether to keep them separate

/* check that this is the first read at this address, for this size
 * this is to be sure that the read value was in the initial state
 * */
bool check_first_read(struct mem_access ma){
    for (auto el : good_reads){
        if (ma.addr < el.addr && el.addr < (ma.addr+ma.size)){
            error("Overlapping mem reads[1], handle this case!");
        }
        if (ma.addr < (el.addr+el.size) && (el.addr+el.size) < (ma.addr+ma.size)){
            error("Overlapping mem reads[2], handle this case!");
        }
        if (ma.addr >= el.addr && (ma.addr+ma.size) <= (el.addr+el.size)){
            //fprintf(stderr, "[XXXXXXX] - pc: %x, addr: %x, size: %x\n", ma.pc, ma.addr, ma.size);
            return false;
        }
    }
    return true;
}

/* check that there were no previous writes to the same memory address, for this size
 * this is because reads that follow writes on the same memory can be computed by KLEE in its execution
 * and they were not part of the initial state
 * */
bool check_no_write(struct mem_access ma){
    for (auto el : writes){
        if (ma.addr < el.addr && el.addr < (ma.addr+ma.size)){
            error("Overlapping mem reads[1], handle this case!");
        }
        if (ma.addr < (el.addr+el.size) && (el.addr+el.size) < (ma.addr+ma.size)){
            error("Overlapping mem reads[2], handle this case!");
        }
        if (ma.addr >= el.addr && (ma.addr+ma.size) <= (el.addr+el.size)){
            return false;
        }
    }
    return true;
}

/* The goal here is to dump the initial memory state, to be used then in the LLVM passes 
 * to populate the global variable guest_memory.
 * We need to take into account only the first time that the content of a memory address is read.
 * */
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size) {
    struct mem_access ma;
    bool check_read = true;
    bool check_write = true;
    // populate the struct
    ma.pc = pc;
    ma.addr = addr;
    ma.size = size;
    ma.buf = (uint8_t *) malloc(size*sizeof(uint8_t));
    panda_virtual_memory_read(env, addr, ma.buf, size);

    check_read = check_first_read(ma);
    check_write = check_no_write(ma);
    
    if (check_read && check_write){
        good_reads.push_back(ma);
    }

    fprintf(stderr, "[mem_read] - pc: %x, addr: %x, size: %x, ", pc, addr, size);
    for (int i=0; i<size; i++){
        fprintf(stderr, "0x%hhx ", ma.buf[i]);
    }
    fprintf(stderr, "\n");

    return 1;
}

bool init_plugin(void *self) {
    panda_cb pcb;

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();

    pcb.virt_mem_before_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_READ, pcb);
    pcb.virt_mem_before_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_WRITE, pcb);

    return true;
}

void uninit_plugin(void *self) {
    fprintf(stderr, "[uninit_plugin] - Initial state:\n");
    int reads_log = open("reads_log.bin", O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
    if(reads_log == -1) {
        printf("Couldn't write report:\n");
        perror("fopen");
        return;
    }

    for (auto ma : good_reads){
        // write to file:
        // address(32bit) || size(32bit) || content(size*8bit)
        // XXX: by fixing the sizes we lose the adaptability of target_ulong
        if (write(reads_log, &ma.addr, 4) != 4){
            fprintf(stderr, "Couldn't write ma.addr\n");
            perror("write");
        }
        if (write(reads_log, &ma.size, 4) != 4){
            fprintf(stderr, "Couldn't write ma.addr\n");
            perror("write");
        }
        if (write(reads_log, ma.buf, ma.size) != ma.size){
            fprintf(stderr, "Couldn't write ma.addr\n");
            perror("write");
        }

        fprintf(stderr, "[mem_read] - pc: %x, addr: %x, size: %x, ", ma.pc, ma.addr, ma.size);
        for (int i=0; i<ma.size; i++){
            fprintf(stderr, "0x%hhx ", ma.buf[i]);
        }
        fprintf(stderr, "\n");
    }

    close(reads_log);
}
