There are some dependencies that have to be changed accordingly when the serial peripheral changes:

- #define GUEST_MEMORY_SIZE 0x100000
    total memory that has been allocated by avatar2 during the recording phase

- #define MAX_SIZE 100
    max size of contiguous reads in memory

- #define SERIAL_START_ADDRESS 0xff000
    start address where the peripheral has been allocated

- in general, the memory layout of the peripheral we want to emulate
