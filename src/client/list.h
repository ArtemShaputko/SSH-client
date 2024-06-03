#ifndef LIST_H
#define LIST_H

#include <libssh/libssh.h>

typedef struct item
{
    ssh_channel channel;
    int fd_in;
    int fd_out;
    int prted;
    struct item *next;
} node_t;

int insert_item(ssh_channel channel, int fd_in, int fd_out,
                int prted);
void delete_item(ssh_channel channel);
node_t *search_item(ssh_channel channel);

#endif