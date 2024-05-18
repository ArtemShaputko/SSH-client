#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "func.h"
#include "../client/client.h"
#include "utils.h"

char known_hosts_file_full_path[PATH_MAX] = {0};

int main(int argc, char *argv[])
{
    cmd_options opts = parse_cmd_options(argc, argv);
    char *home = getenv("HOME");
    if (home == NULL || strcmp(home, "/root") == 0)
    {
        snprintf(known_hosts_file_full_path, PATH_MAX, "/%s", KNOWN_HOSTS_FILE);
    }
    else
    {
        snprintf(known_hosts_file_full_path, PATH_MAX, "%s/%s", home, KNOWN_HOSTS_FILE);
    }
    client_function(&opts);
    return 0;
}
