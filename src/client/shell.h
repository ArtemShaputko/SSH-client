#ifndef SHELL_H
#define SHELL_H

#include <libssh/libssh.h>
int shell_session(ssh_session session);
int make_interactive_shell(ssh_channel channel);
int interactive_shell_session(ssh_session session, ssh_channel channel);

#endif