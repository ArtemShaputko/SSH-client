#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include "func.h"
#include "../client/client.h"
#include "utils.h"

char known_hosts_file_full_path[PATH_MAX] = {0};

int main(int argc, char *argv[])
{
    cmd_options opts = parse_cmd_options(argc, argv);
    client_function(&opts);
    return 0;
}
