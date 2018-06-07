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
// XXX: plugin ported to panda2, starting from https://github.com/panda-re/panda/blob/panda1/qemu/panda_plugins/memdump/memdump.cpp

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

/*
extern "C" {

#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"
#include "disas.h"


}
*/
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

/*
struct prog_point {
    target_ulong caller;
    target_ulong pc;
    target_ulong cr3;
    bool operator <(const prog_point &p) const {
        return (this->pc < p.pc) || \
               (this->pc == p.pc && this->caller < p.caller) || \
               (this->pc == p.pc && this->caller == p.caller && this->cr3 < p.cr3);
    }
};

struct fpos { unsigned long off; };
std::map<prog_point,fpos> read_tracker;
std::map<prog_point,fpos> write_tracker;
FILE *read_log, *write_log;
unsigned char *read_buf, *write_buf;
unsigned long read_sz, write_sz;
*/


/*
int mem_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf,
                       std::map<prog_point,fpos> &tracker, unsigned char *log) {
    prog_point p = {};
#ifdef TARGET_I386
    panda_virtual_memory_rw(env, env->regs[R_EBP]+4, (uint8_t *)&p.caller, 4, 0);
    if((env->hflags & HF_CPL_MASK) != 0) // Lump all kernel-mode CR3s together
        p.cr3 = env->cr[3];
#endif
    p.pc = pc;
    
    //fseek(log, tracker[p].off, SEEK_SET);
    //fwrite((unsigned char *)buf, size, 1, log);
    fpos &fp = tracker[p];
    memcpy(log+fp.off, buf, size);
    fp.off += size;

    return 1;
}

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, write_tracker, write_buf);
}

int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, read_tracker, read_buf);
}
*/

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



    /*
    prog_point p = {};
#ifdef TARGET_I386
    panda_virtual_memory_rw(env, env->regs[R_EBP]+4, (uint8_t *)&p.caller, 4, 0);
    if((env->hflags & HF_CPL_MASK) != 0) // Lump all kernel-mode CR3s together
        p.cr3 = env->cr[3];
#endif
    p.pc = pc;
    write_tracker[p] += size;
    */

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
            //fprintf(stderr, "[XXXXXXX] - pc: %x, addr: %x, size: %x\n", ma.pc, ma.addr, ma.size);
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
    /*
    prog_point p = {};
#ifdef TARGET_I386
    panda_virtual_memory_rw(env, env->regs[R_EBP]+4, (uint8_t *)&p.caller, 4, 0);
    if((env->hflags & HF_CPL_MASK) != 0) // Lump all kernel-mode CR3s together
        p.cr3 = env->cr[3];
#endif
    p.pc = pc;
    read_tracker[p] += size;
    */
 
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






/*
    FILE *read_idx, *write_idx;
    prog_point p = {};
    unsigned long off = 0;
    target_ulong size = 0;

    read_idx = fopen("tap_reads.idx", "r");
    if (read_idx) {
        printf("Calculating read indices...\n");
        fseek(read_idx, 4, SEEK_SET);
        while (!feof(read_idx)) {
            fread(&p, sizeof(p), 1, read_idx);
            fread(&size, sizeof(target_ulong), 1, read_idx);
            read_tracker[p].off = off;
            off += size;
        }

        pcb.virt_mem_read = mem_read_callback;
        panda_register_callback(self, PANDA_CB_VIRT_MEM_READ, pcb);

        read_sz = off;
        read_log = fopen("tap_reads.bin", "w+");
        if (!read_log)
            perror("fopen");
        ftruncate(fileno(read_log), read_sz);

        read_buf = (unsigned char *)mmap(NULL, read_sz, PROT_WRITE, MAP_SHARED, fileno(read_log), 0);
        if (read_buf == MAP_FAILED) perror("mmap");
        if (madvise(read_buf, read_sz, MADV_RANDOM) == -1)
            perror("madvise");
    }

    // reset
    off = 0;
    size = 0;

    write_idx = fopen("tap_writes.idx", "r");
    if (write_idx) {
        printf("Calculating write indices...\n");
        fseek(write_idx, 4, SEEK_SET);
        while (!feof(write_idx)) {
            fread(&p, sizeof(p), 1, write_idx);
            fread(&size, sizeof(target_ulong), 1, write_idx);
            write_tracker[p].off = off;
            off += size;
        }

        pcb.virt_mem_write = mem_write_callback;
        panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);

        write_sz = off;
        write_log = fopen("tap_writes.bin", "w+");
        if (!write_log)
            perror("fopen");
        ftruncate(fileno(write_log), write_sz);

        write_buf = (unsigned char *)mmap(NULL, write_sz, PROT_WRITE, MAP_SHARED, fileno(write_log), 0);
        if (write_buf == MAP_FAILED) perror("mmap");
        if (madvise(write_buf, write_sz, MADV_RANDOM) == -1)
            perror("madvise");
    }

    // */
    return true;
}

void uninit_plugin(void *self) {
    fprintf(stderr, "[uninit_plugin] - Initial state:\n");

    
    // TODO: write file
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
