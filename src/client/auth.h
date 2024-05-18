#ifndef AUTH_H
#define AUTH_H

#include <libssh/libssh.h>

int log_in_pubkey(ssh_session session);
int log_in_kbdint(ssh_session session);
int log_in_password(ssh_session session);
int log_in(ssh_session session);
void display_banner(ssh_session session);

#endif