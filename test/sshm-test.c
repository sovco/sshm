#define SSHM_IMPL
#include <sshm/sshm.h>

#include <stf/stf.h>
#include <sys/wait.h>

#define RUN_CMD(cmd, ...)                                \
    do {                                                 \
        char *const args[] = { cmd, __VA_ARGS__, NULL }; \
        int forkres = -1;                                \
        if ((forkres = fork()) == 0) {                   \
            execv(cmd, args);                            \
        }                                                \
        if (forkres > 0)                                 \
            waitpid(forkres, NULL, 0);                   \
    } while (0)

static inline bool file_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

STF_TEST_CASE(sshm, sshm_shm_open_check_if_shm_object_was_created)
{
    sshm_shm_block block;
    const int res = sshm_shm_open(&block,
        .name = "/sshm_shm_open_check_if_shm_object_was_created",
        .len = 500,
        .flags = (sshm_shm_flags){
            .open_flag = SSHM_OPEN_FLAG_READ_WRITE | SSHM_OPEN_FLAG_CREATE | SSHM_OPEN_FLAG_EXCLUSIVE,
            .permissions = SSHM_PERMISSIONS_USER_ALL,
            .map_prot = SSHM_MAP_PROT_READ | SSHM_MAP_PROT_WRITE,
            .map_type = SSHM_MAP_TYPE_SHARED });

    STF_EXPECT(res == 0, .failure_msg = "sshm_shm_open was not succesful");
    STF_EXPECT(file_exists("/dev/shm/sshm_shm_open_check_if_shm_object_was_created"), .failure_msg = "sshm_shm_open did no yield a shm object");
    RUN_CMD("/usr/bin/rm", "/dev/shm/sshm_shm_open_check_if_shm_object_was_created");
}

STF_TEST_CASE(sshm, sshm_shm_open_check_if_shm_block_returned_valid)
{
    static const char name[255] = "/sshm_shm_open_check_if_shm_block_returned_valid";
    static const size_t len = 500;
    static const sshm_shm_flags flags = (sshm_shm_flags){
        .open_flag = SSHM_OPEN_FLAG_READ_WRITE | SSHM_OPEN_FLAG_CREATE | SSHM_OPEN_FLAG_EXCLUSIVE,
        .permissions = SSHM_PERMISSIONS_USER_ALL,
        .map_prot = SSHM_MAP_PROT_READ | SSHM_MAP_PROT_WRITE,
        .map_type = SSHM_MAP_TYPE_SHARED
    };

    sshm_shm_block block = { 0 };
    const int res = sshm_shm_open(&block,
        .name = &name[0],
        .len = len,
        .flags = flags);

    STF_EXPECT(res == 0, .failure_msg = "sshm_shm_open was not succesful");
    STF_EXPECT(block.len == len, .failure_msg = "len does not match");
    STF_EXPECT(block.name != NULL, .return_on_failure = true, .failure_msg = "name is null");
    STF_EXPECT(strcmp(block.name, &name[0]) == 0, .failure_msg = "name does not match");
    STF_EXPECT(memcmp(&block.flags, &flags, sizeof(flags)) == 0, .return_on_failure = true, .failure_msg = "flags don't match");

    RUN_CMD("/usr/bin/rm", "/dev/shm/sshm_shm_open_check_if_shm_block_returned_valid");
}

STF_TEST_CASE(sshm, sshm_shm_open_check_if_shm_block_data_is_not_null)
{
    static const char name[255] = "/sshm_shm_open_check_if_shm_block_data_is_not_null";
    static const size_t len = 500;
    static const sshm_shm_flags flags = (sshm_shm_flags){
        .open_flag = SSHM_OPEN_FLAG_READ_WRITE | SSHM_OPEN_FLAG_CREATE | SSHM_OPEN_FLAG_EXCLUSIVE,
        .permissions = SSHM_PERMISSIONS_USER_ALL,
        .map_prot = SSHM_MAP_PROT_READ | SSHM_MAP_PROT_WRITE,
        .map_type = SSHM_MAP_TYPE_SHARED
    };

    sshm_shm_block block = { 0 };
    const int res = sshm_shm_open(&block,
        .name = &name[0],
        .len = len,
        .flags = flags);

    STF_EXPECT(res == 0, .failure_msg = "sshm_shm_open was not succesful");
    STF_EXPECT(block.data != NULL, .failure_msg = "data is null");

    RUN_CMD("/usr/bin/rm", "/dev/shm/sshm_shm_open_check_if_shm_block_data_is_not_null");
}

STF_TEST_CASE(sshm, sshm_shm_open_then_close_and_check_if_the_shm_object_still_exists)
{
    static const char name[255] = "/sshm_shm_open_then_close_and_check_if_the_shm_object_still_exists";
    static const size_t len = 500;
    static const sshm_shm_flags flags = (sshm_shm_flags){
        .open_flag = SSHM_OPEN_FLAG_READ_WRITE | SSHM_OPEN_FLAG_CREATE | SSHM_OPEN_FLAG_EXCLUSIVE,
        .permissions = SSHM_PERMISSIONS_USER_ALL,
        .map_prot = SSHM_MAP_PROT_READ | SSHM_MAP_PROT_WRITE,
        .map_type = SSHM_MAP_TYPE_SHARED
    };

    sshm_shm_block block = { 0 };
    const int res = sshm_shm_open(&block,
        .name = &name[0],
        .len = len,
        .flags = flags);

    STF_EXPECT(res == 0, .failure_msg = "sshm_shm_open was not succesful");
    STF_EXPECT(file_exists("/dev/shm/sshm_shm_open_then_close_and_check_if_the_shm_object_still_exists"), .failure_msg = "shm object does not exist");

    STF_EXPECT(sshm_shm_close(&block) == 0, .failure_msg = "sshm_shm_close failed");
    STF_EXPECT(file_exists("/dev/shm/sshm_shm_open_then_close_and_check_if_the_shm_object_still_exists"), .failure_msg = "shm object does not exist after close");

    RUN_CMD("/usr/bin/rm", "/dev/shm/sshm_shm_open_then_close_and_check_if_the_shm_object_still_exists");
}

STF_TEST_CASE(sshm, sshm_shm_open_then_close_and_reopen)
{
    static const char name[255] = "/sshm_shm_open_then_close_and_reopen";
    static const size_t len = 500;
    static const sshm_shm_flags flags = (sshm_shm_flags){
        .open_flag = SSHM_OPEN_FLAG_READ_WRITE | SSHM_OPEN_FLAG_CREATE | SSHM_OPEN_FLAG_EXCLUSIVE,
        .permissions = SSHM_PERMISSIONS_USER_ALL,
        .map_prot = SSHM_MAP_PROT_READ | SSHM_MAP_PROT_WRITE,
        .map_type = SSHM_MAP_TYPE_SHARED
    };

    static const sshm_shm_flags reopen_flags = (sshm_shm_flags){
        .open_flag = SSHM_OPEN_FLAG_READ_WRITE,
        .permissions = SSHM_PERMISSIONS_USER_ALL,
        .map_prot = SSHM_MAP_PROT_READ | SSHM_MAP_PROT_WRITE,
        .map_type = SSHM_MAP_TYPE_SHARED
    };

    sshm_shm_block block = { 0 };
    const int res = sshm_shm_open(&block,
        .name = &name[0],
        .len = len,
        .flags = flags);

    STF_EXPECT(res == 0, .failure_msg = "sshm_shm_open was not succesful");
    STF_EXPECT(block.data != NULL, .failure_msg = "block data is NULL");
    STF_EXPECT(sshm_shm_close(&block) == 0, .failure_msg = "sshm_shm_close failed");

    sshm_shm_block reopen_block = { 0 };
    const int reopen_res = sshm_shm_open(&reopen_block,
        .name = &name[0],
        .len = len,
        .flags = reopen_flags);

    STF_EXPECT(reopen_res == 0, .failure_msg = "sshm_shm_open was not succesful for reopen");
    STF_EXPECT(reopen_block.data != NULL, .failure_msg = "reopen_block data is NULL");

    const int close_after_reopen_res = sshm_shm_close(&reopen_block);

    STF_EXPECT(close_after_reopen_res == 0, .failure_msg = "sshm_shm_close failed for reopen");

    RUN_CMD("/usr/bin/rm", "/dev/shm/sshm_shm_open_then_close_and_reopen");
}

STF_TEST_CASE(sshm, sshm_shm_open_then_destroy_check_shm_obj_still_exists)
{
    static const char name[255] = "/sshm_shm_open_then_destroy_check_shm_obj_still_exists";
    static const size_t len = 500;
    static const sshm_shm_flags flags = (sshm_shm_flags){
        .open_flag = SSHM_OPEN_FLAG_READ_WRITE | SSHM_OPEN_FLAG_CREATE | SSHM_OPEN_FLAG_EXCLUSIVE,
        .permissions = SSHM_PERMISSIONS_USER_ALL,
        .map_prot = SSHM_MAP_PROT_READ | SSHM_MAP_PROT_WRITE,
        .map_type = SSHM_MAP_TYPE_SHARED
    };

    sshm_shm_block block = { 0 };
    const int res = sshm_shm_open(&block,
        .name = &name[0],
        .len = len,
        .flags = flags);

    STF_EXPECT(res == 0, .failure_msg = "sshm_shm_open was not succesful");
    STF_EXPECT(file_exists("/dev/shm/sshm_shm_open_then_destroy_check_shm_obj_still_exists"), .failure_msg = "shm object does not exist");

    STF_EXPECT(sshm_shm_destroy(&block) == 0, .failure_msg = "sshm_shm_close failed");
    STF_EXPECT(!file_exists("/dev/shm/sshm_shm_open_then_destroy_check_shm_obj_still_exists"), .failure_msg = "shm object still exists after shm_destroy");
}

STF_TEST_CASE(sshm, sshm_shm_open_write_read_destroy)
{
    if (file_exists("/dev/shm/sshm_shm_open_write_read_destroy")) {
        RUN_CMD("/usr/bin/rm", "/dev/shm/sshm_shm_open_write_read_destroy");
    }
    static const char *data_to_write = "hey I'm walkin here";
    static const char name[255] = "/sshm_shm_open_write_read_destroy";
    static const size_t len = 50;
    static const sshm_shm_flags write_flags = (sshm_shm_flags){
        .open_flag = SSHM_OPEN_FLAG_READ_WRITE | SSHM_OPEN_FLAG_CREATE | SSHM_OPEN_FLAG_EXCLUSIVE,
        .permissions = SSHM_PERMISSIONS_USER_ALL,
        .map_prot = SSHM_MAP_PROT_WRITE | SSHM_MAP_PROT_READ,
        .map_type = SSHM_MAP_TYPE_SHARED
    };

    static const sshm_shm_flags read_flags = (sshm_shm_flags){
        .open_flag = SSHM_OPEN_FLAG_READ_ONLY,
        .permissions = SSHM_PERMISSIONS_USER_ALL,
        .map_prot = SSHM_MAP_PROT_READ,
        .map_type = SSHM_MAP_TYPE_SHARED
    };

    sshm_shm_block write_block = { 0 };
    const int write_res = sshm_shm_open(&write_block,
        .name = &name[0],
        .len = len,
        .flags = write_flags);
    STF_EXPECT(write_res == 0, .return_on_failure = true, .failure_msg = "sshm_shm_open for write failed");
    STF_EXPECT(write_block.data != NULL, .return_on_failure = true, .failure_msg = "sshm_shm_open data is NULL");
    strcpy(write_block.data, data_to_write);

    sshm_shm_block read_block = { 0 };
    const int read_res = sshm_shm_open(&read_block,
        .name = &name[0],
        .len = len,
        .flags = read_flags);
    STF_EXPECT(read_res == 0, .return_on_failure = true, .failure_msg = "sshm_shm_open for read failed");
    STF_EXPECT(read_block.data != NULL, .return_on_failure = true, .failure_msg = "sshm_shm_open for read yielded NULL");
    STF_EXPECT(strcmp(read_block.data, data_to_write) == 0, .failure_msg = "data does not match");

    STF_EXPECT(sshm_shm_destroy(&write_block) == 0, .failure_msg = "sshm_shm_destroy failed");
    STF_EXPECT(sshm_shm_destroy(&read_block) == 0, .failure_msg = "sshm_shm_destroy failed");
}

STF_TEST_CASE(sshm, sshm_shm_deduct_aligned_len_deduction_len_of_1)
{
    static const size_t len = 1;
    const size_t page_size = sysconf(_SC_PAGESIZE);
    STF_EXPECT(sshm_shm_deduct_aligned_len(len) == page_size, .failure_msg = "aligned len deduction was false");
}

STF_TEST_CASE(sshm, sshm_shm_deduct_aligned_len_deduction_len_of_page_size)
{
    const size_t page_size = sysconf(_SC_PAGESIZE);
    STF_EXPECT(sshm_shm_deduct_aligned_len(page_size) == page_size, .failure_msg = "aligned len deduction was false");
}

STF_TEST_CASE(sshm, sshm_shm_deduct_aligned_len_deduction_len_of_page_size_plus_one)
{
    const size_t page_size = sysconf(_SC_PAGESIZE);
    STF_EXPECT(sshm_shm_deduct_aligned_len(page_size + 1) == 2 * page_size, .failure_msg = "aligned len deduction was false");
}

int main(void)
{
    return STF_RUN_TESTS();
}
