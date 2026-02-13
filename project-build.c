#define NOB_IMPLEMENTATION
#include "build/deps/nob/nob.h"

#define SCLIP_IMPL
#include "project-build.h"

int main(int argc, char **argv)
{
    sclip_parse(argc, (const char **)argv);
    NOB_GO_REBUILD_URSELF(argc, argv);
    Nob_Cmd cmd = { 0 };

    nob_cmd_append(&cmd, "mkdir", "-p", "build/deps/stf");
    if (!nob_cmd_run(&cmd))
        return 1;
    if (!file_exists("build/deps/stf/stf.h")) {
        nob_cmd_append(&cmd, "curl", "-Lo", "build/deps/stf/stf.h",
            "https://raw.githubusercontent.com/sovco/stf/refs/heads/"
            "master/include/stf/stf.h");
        if (!nob_cmd_run(&cmd))
            return 1;
    }
    nob_cmd_append(&cmd, "cc", "-Wall", "-Wextra", "-std=c11");
    if (sclip_opt_debug_is_provided()) {
        nob_cmd_append(&cmd, "-ggdb");
    } else {
        nob_cmd_append(&cmd, "-O3");
    }
    nob_cmd_append(&cmd, "-D_POSIX_C_SOURCE=200112L", "-o", "build/sshm-test", "-lpthread", "-lm", "-Iinclude", "-Ibuild/deps", "test/sshm-test.c");
    if (!nob_cmd_run(&cmd))
        return 1;
    if (sclip_opt_run_tests_is_provided()) {
        nob_cmd_append(&cmd, "./build/sshm-test");
        if (!nob_cmd_run(&cmd))
            return 1;
    }
    return 0;
}
