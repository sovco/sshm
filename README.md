# Simple Shared Memory

This provides a "simpler" API to POSIX shared memory.

# Concept

The main idea is that you open/create an shm_block and write/read to it's .data member.
```c
    sshm_shm_block block = { 0 };
    const int res = sshm_shm_open(&block,
        .name = &name[0], // POSIX paging file name starts with '/' 255 chars long
        .len = 500, // You can use sshm_shm_deduct_aligned_len for page aligned len 
        .flags = (sshm_shm_flags){
            .open_flag = SSHM_OPEN_FLAG_READ_WRITE | SSHM_OPEN_FLAG_CREATE | SSHM_OPEN_FLAG_EXCLUSIVE,
            .permissions = SSHM_PERMISSIONS_USER_ALL,
            .map_prot = SSHM_MAP_PROT_WRITE | SSHM_MAP_PROT_READ,
            .map_type = SSHM_MAP_TYPE_SHARED
        }
    );
    if(res < 0) { // sshm_shm_open on failure returns -errno
        // handle failure like this
    }
    const char *to_write = "writing this to shm-block .data";
    strcpy(block.data, to_write);
    // ...
    
    sshm_shm_close(&block); // This will close fd and dereference .data but will not delete POSIX shm object   
    sshm_shm_destroy(&block); // This will close fd and dereference .data and delete POSIX shm object
);
```

# Build and Run Tests

To build run these commands
```bash
mkdir -p build/deps/nob
curl -Lo build/deps/nob/nob.h https://raw.githubusercontent.com/tsoding/nob.h/refs/heads/main/nob.h
gcc -o project-build project-build.c 
./project-build [--debug | -d] [--run-tests | -T]
```
