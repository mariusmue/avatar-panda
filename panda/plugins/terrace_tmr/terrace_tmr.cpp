#include "qemu/osdep.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "panda/plugin.h"



#include "qapi/error.h"
#include "qapi/qmp/qobject.h"
#include "qapi/qmp/qint.h"
#include "qapi/qmp/qdict.h"

#include <iostream>
#include <fstream>
#include <map>
#include <vector>

extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
#include "qapi/qmp/qjson.h"
}

extern int errno;


std::ofstream mem_dump_file;
std::ofstream smem_trace_file;
std::map<target_ulong,uint8_t> readmap;

/* The data format written to file is address | length | content */
void write_serialized_mem_dump(void)
{
    std::vector<uint8_t> mem;
    target_ulong addr, marker = 0;
    uint32_t size;

    for (auto const& e : readmap) {
        if (e.first == marker+1){
        }
        else if (!mem.empty()){ // mem.empty() only happens on first iter
            addr = marker - mem.size() + 1;
            size = (uint32_t)   mem.size() ;

            mem_dump_file.write( (const char *) &addr, sizeof(target_ulong));
            mem_dump_file.write( (const char *) &size, 4 );
            for (const auto &b : mem) {
                mem_dump_file.write( (const char*) &b, 1);
            }
            mem.clear();
        }

        mem.push_back(e.second);
        marker = e.first;
    }
}



int mem_read_cb(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size, void *buf)
{
    for (int i=0; i<size; i++) {
        //TODO: check for special mem
        if (readmap.count(pc+i)) continue; //did we already log this?
        readmap[pc+i] = ((uint8_t *) buf)[i];
    }

    return 0;
}




static QDict * load_configuration(const char *config_file_name)
{
    QObject * obj;
    std::ifstream ifs(config_file_name);
    std::string conf_json ((std::istreambuf_iterator<char>(ifs)),
            (std::istreambuf_iterator<char>()));
   
    obj = qobject_from_json(conf_json.c_str());

    if (!obj || qobject_type(obj) != QTYPE_QDICT) {
        fprintf(stderr, "Error parsing JSON configuration file\n");
        exit(1);
    }
    return qobject_to_qdict(obj);

}


bool init_plugin(void *self)
{

    panda_arg_list *args = panda_get_args("terrace_tmr");

    const char *nmem_file_name = panda_parse_string_opt(args, "memory_file",
            "dumped_mem.bin", "File to store memory reads for initialization");
    const char *smem_file_name = panda_parse_string_opt(args, "special_memory_file",
            "special_reads.bin", "File storing special memory read");
    const char *config_file_name = panda_parse_string_opt(args, "config_file",
            "conf.json", "JSON file configuring the memory ranges");

    smem_trace_file.open(smem_file_name, std::ios::out | std::ios::binary);
    mem_dump_file.open(nmem_file_name, std::ios::out | std::ios::binary);
 

    load_configuration(config_file_name);



    panda_enable_memcb();

    panda_cb pcb;

    // Assumption: in monolithic memory spaces, virt_mem == phys_mem.
    pcb.virt_mem_after_read = mem_read_cb;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_READ, pcb);

    return true;
}

void uninit_plugin(void *self) {
    write_serialized_mem_dump();
    mem_dump_file.close();
}
