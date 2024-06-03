#ifndef FUNC_H
#define FUNC_H

#include "utils.h"

extern int enableX11;

cmd_options parse_cmd_options(int argc, char *argv[]);
void set_home_host_file(const char *path);
void print_usage();

#endif