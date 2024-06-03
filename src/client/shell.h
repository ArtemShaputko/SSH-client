#ifndef SHELL_H
#define SHELL_H

#include <libssh/libssh.h>
#include <libssh/callbacks.h>

void handle_winch(int sig);
int shell_session(ssh_session session);
int make_interactive_shell(ssh_channel channel, ssh_session session);
int interactive_shell_session(ssh_session session, ssh_channel channel);
ssh_channel x11_open_request_callback(ssh_session session, const char *shost, int sport, void *userdata);
int x11_connect_display(void);
void set_nodelay(int fd);
int connect_local_xsocket(int display_number);
int connect_local_xsocket_path(const char *pathname);
int copy_channel_to_fd_callback(ssh_session session, ssh_channel channel,
                                void *data, uint32_t len, int is_stderr,
                                void *userdata);
void channel_close_callback(ssh_session session, ssh_channel channel,
                            void *userdata);
int copy_channel_to_fd_callback(ssh_session session, ssh_channel channel,
                                void *data, uint32_t len, int is_stderr,
                                void *userdata);
int copy_fd_to_channel_callback(int fd, int revents, void *userdata);
int x11_get_proto(const char *display, char **_proto, char **_cookie);
ssh_channel x11_open_request_callback(ssh_session session, const char *shost, int sport, void *userdata);
int enable_X11(ssh_channel channel, ssh_session session);

#endif