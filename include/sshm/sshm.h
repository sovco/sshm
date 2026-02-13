#ifndef SSHM_H
#define SSHM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/stat.h>

typedef enum sshm_shm_open_flags_t {
    SSHM_OPEN_FLAG_READ_ONLY = O_RDONLY,
    SSHM_OPEN_FLAG_READ_WRITE = O_RDWR,
    SSHM_OPEN_FLAG_CREATE = O_CREAT,
    SSHM_OPEN_FLAG_EXCLUSIVE = O_EXCL,
    SSHM_OPEN_FLAG_TRUNCATE = O_TRUNC
} sshm_shm_open_flags;

typedef enum sshm_shm_permissions_t {
    SSHM_PERMISSIONS_USER_ALL = S_IRWXU,
    SSHM_PERMISSIONS_USER_READ = S_IRUSR,
    SSHM_PERMISSIONS_USER_WRITE = S_IWUSR,
    SSHM_PERMISSIONS_USER_EXECUTE = S_IXUSR,
    SSHM_PERMISSIONS_GROUP_ALL = S_IRWXG,
    SSHM_PERMISSIONS_GROUP_READ = S_IRGRP,
    SSHM_PERMISSIONS_GROUP_WRITE = S_IWGRP,
    SSHM_PERMISSIONS_GROUP_EXECUTE = S_IXGRP,
    SSHM_PERMISSIONS_OTHER_ALL = S_IRWXO,
    SSHM_PERMISSIONS_OTHER_READ = S_IROTH,
    SSHM_PERMISSIONS_OTHER_WRITE = S_IWOTH,
    SSHM_PERMISSIONS_OTHER_EXECUTE = S_IXOTH
} sshm_shm_permissions;

typedef enum sshm_shm_map_prot_t {
    SSHM_MAP_PROT_READ = PROT_READ,
    SSHM_MAP_PROT_WRITE = PROT_WRITE,
    SSHM_MAP_PROT_EXEC = PROT_EXEC,
    SSHM_MAP_PROT_NONE = PROT_NONE
} sshm_shm_map_prot;

typedef enum sshm_shm_map_type_t {
    SSHM_MAP_TYPE_SHARED = MAP_SHARED,
    SSHM_MAP_TYPE_PRIVATE = MAP_PRIVATE,
    SSHM_MAP_TYPE_FIXED = MAP_FIXED,
} sshm_shm_map_type;

typedef struct sshm_shm_flags_t
{
    const sshm_shm_open_flags open_flag;
    const sshm_shm_permissions permissions;
    const sshm_shm_map_prot map_prot;
    const sshm_shm_map_type map_type;
} sshm_shm_flags;

typedef struct sshm_shm_block_creation_data_t
{
    const char *const name;
    const size_t len;
    const sshm_shm_flags flags;
} sshm_shm_block_creation_data;

typedef struct sshm_shm_block_t
{
    const char *const name;
    void *const data;
    const sshm_shm_flags flags;
    const size_t len;
    const int fd;
} sshm_shm_block;


#define sshm_shm_open(block, ...) \
    __sshm_shm_open(block, (sshm_shm_block_creation_data){ __VA_ARGS__ })
static inline int __sshm_shm_open(sshm_shm_block *const restrict block, const sshm_shm_block_creation_data creation_data);
static inline int sshm_shm_close(const sshm_shm_block *const restrict block);
static inline int sshm_shm_destroy(const sshm_shm_block *const restrict block);
static inline size_t sshm_shm_deduct_aligned_len(const size_t len);

#ifdef __cplusplus
}// extern "C"
#endif

#ifdef SSHM_IMPL

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

static inline int __sshm_shm_open(sshm_shm_block *const restrict block, const sshm_shm_block_creation_data creation_data)
{
    const int fd = shm_open(creation_data.name, creation_data.flags.open_flag, creation_data.flags.permissions);
    if (fd < 0) return -errno;
    if (creation_data.flags.open_flag & SSHM_OPEN_FLAG_CREATE) {
        if (ftruncate(fd, (off_t)creation_data.len) < 0) {
            return -errno;
        }
    }
    void *data = mmap(NULL, creation_data.len, creation_data.flags.map_prot, creation_data.flags.map_type, fd, 0);
    if (data == MAP_FAILED) {
        return -errno;
    }
    sshm_shm_block tmp = (sshm_shm_block){ .data = data,
        .name = creation_data.name,
        .len = creation_data.len,
        .fd = fd,
        .flags = creation_data.flags };
    memcpy(block, &tmp, sizeof(*block));
    return 0;
}

static inline int sshm_shm_close(const sshm_shm_block *const restrict block)
{
    if (close(block->fd) < 0) {
        return -errno;
    }
    if (munmap(block->data, block->len) < 0) {
        return -errno;
    }
    return 0;
}

static inline int sshm_shm_destroy(const sshm_shm_block *const restrict block)
{
    struct stat stats = { 0 };
    if (fstat(block->fd, &stats) < 0) {
        return -errno;
    }
    const int close_res = sshm_shm_close(block);
    if (close_res < 0) {
        return close_res;
    }
    if (stats.st_nlink > 0) {
        if (shm_unlink(block->name) < 0) {
            return -errno;
        }
    }
    return 0;
}

static inline size_t sshm_shm_deduct_aligned_len(const size_t len)
{
    const size_t page_size = sysconf(_SC_PAGESIZE);
    const size_t mod = (len % page_size > 0) ? 1 : 0;
    return page_size * ((len / page_size) + mod);
}

#ifdef __cplusplus
}// extern "C"
#endif

#endif// SMQ_IMPL
#endif// SSHM_H
