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
#include <sstream>

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>


//MM endainness fix for now
#include <byteswap.h>

using namespace std;

static bool make_symbolic = false;
static vector<uint32_t> symb_addrs;

#define GUEST_MEMORY_SIZE 0x100000 
#define MAX_SIZE 100

#define SERIAL_START_ADDRESS 0xff000
#define SERIAL_DR SERIAL_START_ADDRESS
#define SERIAL_FR SERIAL_START_ADDRESS + 0x18

vector<struct mem_access> serial_reads_DR;
vector<struct mem_access> serial_reads_FR;


// #TODO: implement address resolution
int implement_GEP(int address);

struct gm_info {
    int start_address;
    int size;
    unsigned char *gm_chunk; 
};

struct gm_info *gm_reads;
struct gm_info *gm_writes;

int n_records = 0;

int allocate_guest_memory_chunks(){
    int i, size;
    int reads_log;
    int start_address;

    // allocate guest_memory according to the memory ranges that are specified in guest_memory.bin
    reads_log = open("guest_memory.bin", O_RDONLY);
    if (reads_log == -1){
        printf("Couldn't open guest_memory.bin:\n");
        perror("fopen");
        exit(3);
    }

    printf("n_records: %d\n", n_records);
    // first of all, read the number of records
    if (read(reads_log, &n_records, 4) != 4){
        printf("Couldn't read n_records\n");
        perror("write");
        exit(3);
    }

    printf("n_records: %d\n", n_records);
    n_records = __bswap_32 (n_records);    

    printf("n_records: %d\n", n_records);

    printf("Allocating chunks of guest_memory:\n");
    gm_reads = (struct gm_info *) calloc (n_records, sizeof(struct gm_info));
    gm_writes = (struct gm_info *) calloc (n_records, sizeof(struct gm_info));

    for (i=0; i<n_records; i++){
        if(read(reads_log, &start_address, 4) != 4){
            printf("Couldn't read address\n");
            perror("write");
            exit(3);
        }
        if (read(reads_log, &size, 4) != 4){
            printf("Couldn't read size\n");
            perror("write");
            exit(3);
        }
	start_address = __bswap_32(start_address);
	size = __bswap_32(size);
        printf("address: 0x%x, size: 0x%x\n", start_address, size);

	
        gm_reads[i].start_address = start_address;
        gm_reads[i].size = size;
        gm_reads[i].gm_chunk = (uint8_t *) calloc (size, sizeof(uint8_t));

        gm_writes[i].start_address = start_address;
        gm_writes[i].size = size;
        gm_writes[i].gm_chunk = (uint8_t *) calloc (size, sizeof(uint8_t));
    }
    return 0;
}

/*
int resolve_address(int address){
    int i;
    int offset;
    int target_byte;

    for (i=0; i<n_records; i++){
        // check if it's the right chunk
        //printf("start_address: 0x%x\n", gm_array[i].start_address);
        //printf("size: 0x%x\n", gm_array[i].size);
        //printf("address: 0x%x\n", address);
        //printf("start_address+size: 0x%x\n", gm_array[i].start_address + gm_array[i].size);

        if (gm_array[i].start_address <= address  &&  (gm_array[i].start_address + gm_array[i].size) > address){
            break;
        }
    }
    if (i>=n_records){
        printf("address 0x%x does not belong to any allocated gm_chunk\n", address);
        exit(1);
    }
    offset = address - gm_array[i].start_address;
    //printf("offset: 0x%x\n", offset);
    target_byte = gm_array[i].gm_chunk[offset];
    
    return target_byte;
}
*/




uint8_t read_gm_writes(target_ulong address){
    int i;
    int offset;
    uint8_t target_byte;

    for (i=0; i<n_records; i++){
        if (gm_writes[i].start_address <= address  &&  (gm_writes[i].start_address + gm_writes[i].size) > address){
            break;
        }
    }
    if (i>=n_records){
        printf("address 0x%x does not belong to any allocated gm_chunk\n", address);
        exit(1);
    }
    offset = address - gm_writes[i].start_address;
    //printf("offset: 0x%x\n", offset);
    target_byte = gm_writes[i].gm_chunk[offset];
    
    return target_byte;
}

void write_gm_writes(target_ulong address, uint8_t target_byte){
    int i;
    int offset;

    for (i=0; i<n_records; i++){
        if (gm_writes[i].start_address <= address  &&  (gm_writes[i].start_address + gm_writes[i].size) > address){
            break;
        }
    }
    if (i>=n_records){
        printf("address 0x%x does not belong to any allocated gm_chunk\n", address);
        exit(1);
    }
    offset = address - gm_writes[i].start_address;
    //printf("offset: 0x%x\n", offset);
    gm_writes[i].gm_chunk[offset] = target_byte;
}

uint8_t read_gm_reads(target_ulong address){
    int i;
    int offset;
    uint8_t target_byte;

    for (i=0; i<n_records; i++){
        if (gm_reads[i].start_address <= address  &&  (gm_reads[i].start_address + gm_reads[i].size) > address){
            break;
        }
    }
    if (i>=n_records){
        printf("address 0x%x does not belong to any allocated gm_chunk\n", address);
        exit(1);
    }
    offset = address - gm_reads[i].start_address;
    //printf("offset: 0x%x\n", offset);
    target_byte = gm_reads[i].gm_chunk[offset];
    
    return target_byte;
}

void write_gm_reads(target_ulong address, uint8_t target_byte){
    int i;
    int offset;

    for (i=0; i<n_records; i++){
        if (gm_reads[i].start_address <= address  &&  (gm_reads[i].start_address + gm_reads[i].size) > address){
            break;
        }
    }
    if (i>=n_records){
        printf("address 0x%x does not belong to any allocated gm_chunk\n", address);
        exit(1);
    }
    offset = address - gm_reads[i].start_address;
    //printf("offset: 0x%x\n", offset);
    gm_reads[i].gm_chunk[offset] = target_byte;
}










// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size);
}

struct mem_access {
    target_ulong pc;
    target_ulong addr;
    target_ulong size;
    uint8_t *buf;
};

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    int i;
    // populate guest_memory_writes
    for (i=0; i<size; i++){
        //if (guest_memory_writes[addr+i] != 0){
        if (read_gm_writes(addr+i) != 0){
            write_gm_writes((addr+i), ((uint8_t *)buf)[i]);
        }
    }
    fprintf(stderr, "[mem_write] - pc: %x, addr: %x, size: %x, ", pc, addr, size);
    for (int i=0; i<size; i++){
        fprintf(stderr, "0x%hhx ", ((uint8_t *)buf)[i]);
    }
    fprintf(stderr, "\n");

    return 1;
}

void error(std::string message){
    cerr << "=================================================\n";
    cerr << "   [my_memdump] - ERROR: " << message << endl;
    cerr << "=================================================\n";
    exit(1);
}

/* The goal here is to dump the initial memory state, to be used then in the LLVM passes 
 * to populate the global variable guest_memory.
 * We need to take into account only the first time that the content of a memory address is read.
 * */
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    int i;
    struct mem_access ma;
    // populate guest_memory_reads
    if (addr == SERIAL_DR){
        fprintf(stderr, "[SERIAL_DR] - pc: %x, addr: %x, size: %x, ", pc, addr, size);
        for (int i=0; i<size; i++){
            fprintf(stderr, "0x%hhx ", ((uint8_t *)buf)[i]);
        }
        fprintf(stderr, "\n");
        if (size != 4){
            error("size != 4");
        }
        // populate the struct
        ma.pc = pc;
        ma.addr = addr;
        ma.size = size;
        ma.buf = (uint8_t *) malloc(size*sizeof(uint8_t));
        memcpy(ma.buf, buf, size);

        serial_reads_DR.push_back(ma);
        return 0;
    }
    if (addr == SERIAL_FR){
        fprintf(stderr, "[SERIAL_FR] - pc: %x, addr: %x, size: %x, ", pc, addr, size);
        for (int i=0; i<size; i++){
            fprintf(stderr, "0x%hhx ", ((uint8_t *)buf)[i]);
        }
        fprintf(stderr, "\n");
        if (size != 4){
            error("size != 4");
        }
        // populate the struct
        ma.pc = pc;
        ma.addr = addr;
        ma.size = size;
        ma.buf = (uint8_t *) malloc(size*sizeof(uint8_t));
        memcpy(ma.buf, buf, size);

        serial_reads_FR.push_back(ma);
        return 0;
    }
    for (i=0; i<size; i++){
        //if (guest_memory_reads[addr+i] == 0 && guest_memory_writes[addr+i] == 0){
        if (read_gm_reads(addr+i) == 0 && read_gm_writes(addr+i) == 0){
            //guest_memory_reads[addr+i] = ((uint8_t *)buf)[i];
            write_gm_reads(addr+i, ((uint8_t *)buf)[i]);
        }
    }
    fprintf(stderr, "[mem_read] - pc: %x, addr: %x, size: %x, ", pc, addr, size);
    for (int i=0; i<size; i++){
        fprintf(stderr, "0x%hhx ", ((uint8_t *)buf)[i]);
    }
    fprintf(stderr, "\n");

    return 1;
}

vector<uint32_t> parse_list_addrs(const string& s)
{
    vector<uint32_t> addrs;
    string token;
    istringstream tokenStream(s);
    while (getline(tokenStream, token, '|')) {
        uint32_t x = stoul(token, nullptr, 16);
        addrs.push_back(x);
    }
    return addrs;
}

bool init_plugin(void *self) {
    panda_cb pcb;

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();

    panda_arg_list *args = panda_get_args("my_memdump");
    if (args != NULL) {
        make_symbolic = panda_parse_bool_opt(args, "make_symbolic", "Mark all memory accesses as symbolic");
        if (make_symbolic) {
            const char *addr_list = NULL;
            addr_list = panda_parse_string_opt(args, "addrs", "", "List of adresses in hex, pipe char separated, to be marked as symbolic");
            std::string addresses(addr_list);
            symb_addrs = parse_list_addrs(addresses);
            if (symb_addrs.size() <= 0) {
                fprintf(stderr, "error: empty list of addresses\n");
                return false;
            }
        }
    }

    // initialize guest_memory
    allocate_guest_memory_chunks();

    pcb.virt_mem_after_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_READ, pcb);
    pcb.virt_mem_before_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_WRITE, pcb);

    return true;
}

void uninit_plugin(void *self) {
    fprintf(stderr, "[uninit_plugin] - Initial state:\n");
    int reads_log;
    int serial_reads_log;
    uint32_t i, start_address;
    int size=0;
    struct mem_access *ma;
    bool storing_bytes = false;
    uint8_t *tmp_buf;

    reads_log = open("reads_log.bin", O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
    if(reads_log == -1) {
        printf("Couldn't write report:\n");
        perror("fopen");
        return;
    }
    serial_reads_log = open("serial_reads_log.bin", O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
    if(serial_reads_log == -1) {
        printf("Couldn't write report:\n");
        perror("fopen");
        return;
    }

    char sym_flag;
    for (auto ma : serial_reads_DR){
        // write to file:
        // address(32bit) || size(32bit) || content(size*8bit) || marked as symbolic or not 
        // XXX: by fixing the sizes we lose the adaptability of target_ulong
        if (write(serial_reads_log, &ma.addr, 4) != 4){
            fprintf(stderr, "Couldn't write ma.addr\n");
            perror("write");
        }
        if (write(serial_reads_log, &ma.size, 4) != 4){
            fprintf(stderr, "Couldn't write ma.size\n");
            perror("write");
        }
        if (write(serial_reads_log, ma.buf, ma.size) != ma.size){
            fprintf(stderr, "Couldn't write ma.buf\n");
            perror("write");
        }

        if (std::find(symb_addrs.begin(), symb_addrs.end(), ma.addr) != symb_addrs.end()) {
            sym_flag = 0x01;
            fprintf(stderr, "[memdump] - make 0x%x symbolic\n", ma.addr);
        } else {
            sym_flag = 0x00;
            fprintf(stderr, "[memdump] - DR make 0x%x not symbolic\n", ma.addr);
        }

        if (write(serial_reads_log, &sym_flag, 1) != 1){
            fprintf(stderr, "Couldn't write ma.is_symbolic\n");
            perror("write");
        }
    }

    for (auto ma : serial_reads_FR){
        // write to file:
        // address(32bit) || size(32bit) || content(size*8bit) || marked as symbolic or not 
        // XXX: by fixing the sizes we lose the adaptability of target_ulong
        if (write(serial_reads_log, &ma.addr, 4) != 4){
            fprintf(stderr, "Couldn't write ma.addr\n");
            perror("write");
        }
        if (write(serial_reads_log, &ma.size, 4) != 4){
            fprintf(stderr, "Couldn't write ma.size\n");
            perror("write");
        }
        if (write(serial_reads_log, ma.buf, ma.size) != ma.size){
            fprintf(stderr, "Couldn't write ma.buf\n");
            perror("write");
        }

        if (std::find(symb_addrs.begin(), symb_addrs.end(), ma.addr) != symb_addrs.end()) {
            sym_flag = 0x01;
            fprintf(stderr, "[memdump] - make 0x%x symbolic\n", ma.addr);
        } else {
            fprintf(stderr, "[memdump] - FR make 0x%x not symbolic\n", ma.addr);
            sym_flag = 0x00;
        }

        if (write(serial_reads_log, &sym_flag, 1) != 1){
            fprintf(stderr, "Couldn't write ma.is_symbolic\n");
            perror("write");
        }
    }

    tmp_buf = (uint8_t *) calloc(MAX_SIZE , sizeof(uint8_t));
    //for (i=0; i<GUEST_MEMORY_SIZE; i++){
    int j;
    for (j=0; j<n_records; j++){
        for (i=0; i<gm_reads[j].size; i++){
            if (gm_reads[j].gm_chunk[i] != 0 && size < MAX_SIZE){
                if (! storing_bytes){
                    start_address = gm_reads[j].start_address + i;
                    storing_bytes = true;
                }
                tmp_buf[size++] = gm_reads[j].gm_chunk[i];
            }
            else{
                if (! storing_bytes){
                    continue;
                }
                // populate the mem_access structure
                ma = (struct mem_access *) malloc(sizeof(struct mem_access));
                ma->addr = start_address;
                ma->size = size;
                ma->buf = (uint8_t *) malloc(size*sizeof(uint8_t));
                memcpy(ma->buf, tmp_buf, size);
                
                // write to file
                // address(32bit) || size(32bit) || content(size*8bit)
                // XXX: by fixing the sizes we lose the adaptability of target_ulong
                if (write(reads_log, &ma->addr, 4) != 4){
                    fprintf(stderr, "Couldn't write ma->addr\n");
                    perror("write");
                }
                if (write(reads_log, &ma->size, 4) != 4){
                    fprintf(stderr, "Couldn't write ma->addr\n");
                    perror("write");
                }
                if (write(reads_log, ma->buf, ma->size) != ma->size){
                    fprintf(stderr, "Couldn't write ma->addr\n");
                    perror("write");
                }

                fprintf(stderr, "[mem_read] - pc: %x, addr: %x, size: %x, ", ma->pc, ma->addr, ma->size);
                for (int i=0; i<ma->size; i++){
                    fprintf(stderr, "0x%hhx ", ma->buf[i]);
                }
                fprintf(stderr, "\n");

                // free the structure
                free(ma->buf);
                free(ma);
                free(tmp_buf);
                tmp_buf = (uint8_t *) calloc(MAX_SIZE , sizeof(uint8_t));
                size = 0;
                storing_bytes = false;
            }


        }
    }
    close(reads_log);
    close(serial_reads_log);
}


