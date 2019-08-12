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
#include <algorithm>
#include <sstream>

extern "C" {
#include "qapi/qmp/qjson.h"

    bool init_plugin(void *);
    void uninit_plugin(void *);
}

#include "tmr.pb.h"

extern int errno;

/*  We need to store every byte for special memory, which can also be symbolic.
 *  We will use an extra flag field to encode it's type.
 *  This way, the file containing special memory accesses can be edited
 *  afterwards without running PANDA again.
 */
#define IS_SPECIAL 0x01
#define IS_SYMBOLIC 0x02
#define IS_ROM 0x04


namespace {

struct mem_range_t {
    mem_range_t(target_ulong a, uint32_t s, uint8_t f): addr(a), size(s), flags(f){}
    target_ulong addr;
    uint32_t size;
    uint8_t flags;
};

const char * nmem_file_name;
const char * smem_file_name;

std::map<target_ulong,uint8_t> readmap;
std::map<target_ulong, std::vector<std::tuple<uint8_t, uint8_t>>> special_read_map;
std::vector<mem_range_t> memory_ranges;
std::ofstream log_file;
}


void add_read(TMRNormalReads& reads, target_ulong addr, std::vector<uint8_t> &mem) {
    TMRNormalMemoryRead *read_entry = reads.add_reads();
    read_entry->set_address(addr);
    read_entry->set_content(mem.data(), mem.size()) ;
}

/* Writes a TMRNormalReads Message to disk (c.f. tmr.proto) */
void write_serialized_memory_map(void)
{
    TMRNormalReads reads;
    //std::string mem;
    std::vector<uint8_t> mem;
    target_ulong marker = 0;

    std::ofstream file;
        

    for (auto const& e : readmap) {
        if (mem.empty()){ // Deal with first iteration
            mem.push_back(e.second);
            marker = e.first;
            continue;
        }
        if (e.first == marker + mem.size() ){
            mem.push_back(e.second);
        }
        else {
            add_read( reads, marker, mem);
            mem.clear();
            marker = e.first;
            mem.push_back(e.second);
        }
    }
    add_read( reads, marker, mem);

    file.open(nmem_file_name, std::ios::out | std::ios::binary);
    
    if (!file) {
        std::cerr << "Failed to open " << nmem_file_name << ":" << strerror(errno) << std::endl;
        exit(1);
    }
    
    reads.SerializeToOstream(&file);

}

/* Writes a TMRSpecialReads Message to disk (c.f. tmr.proto) */
void write_serialized_special_memory_map(void)
{

    TMRSpecialReads reads;
    std::ofstream file;

    for (auto const& e :  special_read_map) {
        TMRSpecialMemoryRead *spec_read = reads.add_reads();

        assert(!e.second.empty());

        spec_read->set_address(e.first);
        for (auto const &elem : e.second) {
            uint8_t val, flags;
            std::tie (val, flags) = elem;

            TMRByte *b = spec_read->add_tmr_bytes();
            b->set_value(val);
            if (flags & IS_SYMBOLIC) b->set_is_symbolic(true);
            if (flags & IS_SPECIAL) b->set_is_special(true);
            if (flags & IS_ROM) b->set_is_rom(true);
        }
    }

    file.open(smem_file_name, std::ios::out | std::ios::binary);

    if (!file) {
        std::cerr << "Failed to open " << smem_file_name << ":" << strerror(errno) << std::endl;
        exit(1);
    }

    reads.SerializeToOstream(&file);
}

/*
 * This callback splits the memory accesses to byte-sized chunks and logs them,
 * depending on the flags for the cell in the memory_ranges vector.
 * Note that this implementation does not log at all if the access is not within
 * a defined memory_range.
 */
int mem_read_cb(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size, void *buf)
{

    // Nasty hack, but for testing, the ARM binary will use two fixed ASIDs
    if( !(panda_current_asid(cpu) == 0x72a2db0 || panda_current_asid(cpu) == 0x72a0000 || panda_current_asid(cpu) == 0x72a3ffc )) return 0;

    for (int i=0; i<size; i++) {
        uint8_t val = ((uint8_t *) buf)[i];
        target_ulong address = addr + i;

        // We need to resolve everytime for accesses accross boundaries
        auto mem_range = std::find_if(memory_ranges.begin(), memory_ranges.end(),
                [address](mem_range_t m) {return ((m.addr <= address) && (address <= m.addr + m.size));});
        // Validate that we want to log this access
        if (mem_range == memory_ranges.end() || mem_range->flags & IS_ROM) continue; 

        if (i == 0)
            log_file << std::hex << pc << "    " << addr << std::endl;

        // Log special accesses to our special map
        if ( (mem_range->flags & IS_SPECIAL) || (mem_range->flags & IS_SYMBOLIC)) {
            special_read_map[address].emplace_back( val, mem_range->flags);
        } else { // Log normal accesses
            if (readmap.count(address)) continue; //did we already log this?
            readmap[address] = val;
        }
    }
    return 0;
}


#define QDICT_ASSERT_KEY_TYPE(_dict, _key, _type) \
    g_assert(qdict_haskey(_dict, _key) && qobject_type(qdict_get(_dict, _key)) == _type)

// Parses the configuration file generated by avatar
void load_configuration(const char *config_file_name)
{
    QObject *obj;
    QDict *mapping, *conf;
    QList *memories;
    QListEntry *entry;
    target_ulong address;
    uint32_t size;

    std::ifstream ifs(config_file_name);
    std::string conf_json ((std::istreambuf_iterator<char>(ifs)),
            (std::istreambuf_iterator<char>()));
   
    obj = qobject_from_json(conf_json.c_str());

    if (!obj || qobject_type(obj) != QTYPE_QDICT) {
        fprintf(stderr, "[TMR] Error parsing JSON configuration file\n");
        exit(1);
    }

    conf = qobject_to_qdict(obj);

    memories = qobject_to_qlist(qdict_get(conf, "memory_mapping"));
    g_assert(memories);

    QLIST_FOREACH_ENTRY(memories, entry)
    {
        uint8_t flags = 0;
        mapping = qobject_to_qdict(entry->value);
        QDICT_ASSERT_KEY_TYPE(mapping, "size", QTYPE_QINT);
        QDICT_ASSERT_KEY_TYPE(mapping, "address", QTYPE_QINT);

        size = qdict_get_int(mapping, "size");
        address = qdict_get_int(mapping, "address");

        if (qdict_haskey(mapping, "is_rom") && qdict_get_bool(mapping, "is_rom"))
            flags |= IS_ROM;

        if (qdict_haskey(mapping, "is_symbolic") && qdict_get_bool(mapping, "is_symbolic"))
            flags |= IS_SYMBOLIC;

        if (qdict_haskey(mapping, "is_special") && qdict_get_bool(mapping, "is_special"))
            flags |= IS_SPECIAL;

        memory_ranges.emplace_back( address, size, flags );
        printf("Adding range with flags: %x\n", flags);

    }

}


bool init_plugin(void *self)
{

    panda_arg_list *args = panda_get_args("terrace_tmr");

    nmem_file_name = panda_parse_string_opt(args, "memory_file",
            "dumped_mem.bin", "File to store memory reads for initialization");
    smem_file_name = panda_parse_string_opt(args, "special_memory_file",
            "special_reads.bin", "File storing special memory read");
    const char *config_file_name = panda_parse_string_opt(args, "config_file",
            "conf.json", "JSON file configuring the memory ranges");

    load_configuration(config_file_name);

    log_file.open("mem_callbacks_logged", std::ios::out);


    panda_enable_memcb();

    panda_cb pcb;

    // Assumption: in monolithic memory spaces, virt_mem == phys_mem.
    pcb.virt_mem_after_read = mem_read_cb;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_READ, pcb);

    return true;
}

void uninit_plugin(void *self) {
    write_serialized_memory_map();
    write_serialized_special_memory_map();

    log_file.close();
}
