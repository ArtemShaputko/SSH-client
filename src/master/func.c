#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "func.h"

cmd_options parse_cmd_options(int argc, char *argv[])
{
    int opt;
    cmd_options options = {0};
    if (argc < 2)
    {
        print_usage();
        exit(1);
    }
    char *second_str;
    if ((second_str = strchr(argv[1], '@')) == NULL)
    {
        print_usage();
        exit(1);
    }
    size_t size = (size_t)(second_str - argv[1]) > 20 ? 20 : (size_t)(second_str - argv[1]);
    strncpy(options.user_name, argv[1], size);
    strncpy(options.host_ip, second_str + 1, 20);
    while ((opt = getopt(argc, argv, "p:k:")) != -1)
    {
        switch (opt)
        {
        case 'p':
            options.port = optarg;
            break;
        case 'k':
            options.key_file = optarg;
            break;
        }
    }
    return options;
}

void print_usage()
{
    fprintf(stderr,
            "Usage: sc [user]@[server ip]\n"
            "          [-p port][-h host][-u user]\n"
            "          [-k key_file]\n");
}