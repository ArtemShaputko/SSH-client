#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <sys/types.h>
#include <poll.h>

#include "shell.h"
#include "list.h"
#include "../master/func.h"

#define _PATH_UNIX_X "/tmp/.X11-unix/X%d"
#define _XAUTH_CMD "/usr/bin/xauth list %s 2>/dev/null"

ssh_channel general_channel;
ssh_channel x11channel = NULL;
short events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;
ssh_event event;

struct ssh_channel_callbacks_struct channel_cb = {
    .channel_data_function = copy_channel_to_fd_callback,
    .channel_eof_function = channel_close_callback,
    .channel_close_function = channel_close_callback,
    .userdata = NULL};

struct ssh_callbacks_struct cb = {
    .channel_open_request_x11_function = x11_open_request_callback,
    .userdata = NULL};

void handle_winch(int sig)
{
    if (sig == SIGWINCH)
    {
        struct winsize ws;
        ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws);
        ssh_channel_change_pty_size(general_channel, ws.ws_col, ws.ws_row);
    }
}

int copy_channel_to_fd_callback(ssh_session session, ssh_channel channel,
                                void *data, uint32_t len, int is_stderr,
                                void *userdata)
{
    node_t *temp_node = NULL;
    int fd, sz;

    (void)session;
    (void)is_stderr;
    (void)userdata;

    temp_node = search_item(channel);

    fd = temp_node->fd_out;

    sz = write(fd, data, len);

    return sz;
}

void channel_close_callback(ssh_session session, ssh_channel channel,
                            void *userdata)
{
    node_t *temp_node = NULL;

    (void)session;
    (void)userdata;

    temp_node = search_item(channel);

    if (temp_node != NULL)
    {
        int fd = temp_node->fd_in;

        delete_item(channel);
        ssh_event_remove_fd(event, fd);

        if (temp_node->prted == 0)
        {
            close(fd);
        }
    }
}

ssh_channel x11_open_request_callback(ssh_session session, const char *shost, int sport, void *userdata)
{
    ssh_channel channel = NULL;
    int sock, rv;

    (void)shost;
    (void)sport;
    (void)userdata;

    channel = ssh_channel_new(session);

    sock = x11_connect_display();

    rv = insert_item(channel, sock, sock, 0);
    if (rv != 0)
    {
        ssh_channel_free(channel);
        return NULL;
    }

    ssh_event_add_fd(event, sock, events, copy_fd_to_channel_callback, channel);
    ssh_event_add_session(event, session);

    ssh_add_channel_callbacks(channel, &channel_cb);

    return channel;
}

int copy_fd_to_channel_callback(int fd, int revents, void *userdata)
{
    ssh_channel channel = (ssh_channel)userdata;
    char buf[2097152];
    int sz = 0;

    node_t *temp_node = search_item(channel);

    if (channel == NULL)
    {
        if (temp_node->prted == 0)
        {
            close(fd);
        }
        return -1;
    }

    if (fcntl(fd, F_GETFD) == -1)
    {
        ssh_channel_close(channel);
        return -1;
    }

    if ((revents & POLLIN) || (revents & POLLPRI))
    {
        sz = read(fd, buf, sizeof(buf));
        if (sz > 0)
        {
            ssh_channel_write(channel, buf, sz);
        }
        else if (sz < 0)
        {
            ssh_channel_close(channel);
            return -1;
        }
        else
        {
            /* sz = 0. Why the hell I'm here? */
            if (temp_node->prted == 0)
            {
                close(fd);
            }
            return -1;
        }
    }

    if ((revents & POLLHUP) || (revents & POLLNVAL) || (revents & POLLERR))
    {
        ssh_channel_close(channel);
        return -1;
    }

    return sz;
}

int shell_session(ssh_session session)
{
    ssh_channel channel;
    int result;
    struct termios tty_params;
    struct termios raw_tty_params;

    tcgetattr(0, &tty_params);
    cfmakeraw(&raw_tty_params);

    channel = ssh_channel_new(session);
    if (channel == NULL)
        return SSH_ERROR;

    result = ssh_channel_open_session(channel);
    if (result != SSH_OK)
    {
        ssh_channel_free(channel);
        return result;
    }

    tcsetattr(0, TCSANOW, &raw_tty_params);

    if ((result = make_interactive_shell(channel, session) >= 0))
    {
        interactive_shell_session(session, channel);
    }

    tcsetattr(0, TCSANOW, &tty_params);

    ssh_channel_close(channel);
    ssh_channel_send_eof(channel);
    ssh_channel_free(channel);

    return result;
}

int x11_get_proto(const char *display, char **_proto, char **_cookie)
{
    char cmd[1024], line[512], xdisplay[512];
    static char proto[512], cookie[512];
    FILE *f = NULL;
    int ret = 0;

    *_proto = proto;
    *_cookie = cookie;

    proto[0] = cookie[0] = '\0';

    if (strncmp(display, "localhost:", 10) == 0)
    {
        ret = snprintf(xdisplay, sizeof(xdisplay), "unix:%s", display + 10);
        if (ret < 0 || (size_t)ret >= sizeof(xdisplay))
        {
            return -1;
        }
        display = xdisplay;
    }

    snprintf(cmd, sizeof(cmd), _XAUTH_CMD, display);

    f = popen(cmd, "r");
    if (f && fgets(line, sizeof(line), f) &&
        sscanf(line, "%*s %511s %511s", proto, cookie) == 2)
    {
        ret = 0;
    }
    else
    {
        ret = 1;
    }

    if (f)
    {
        pclose(f);
    }

    return ret;
}

int make_interactive_shell(ssh_channel channel, ssh_session session)
{
    int result;
    struct winsize ws;
    general_channel = channel;

    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) < 0)
    {
        perror("window size");
        return 1;
    }

    result = ssh_channel_request_pty(channel);
    if (result != SSH_OK)
        return result;
    result = ssh_channel_change_pty_size(channel, ws.ws_col, ws.ws_row);
    if (result != SSH_OK)
        return result;
    if (enableX11 == 1)
    {
        result = enable_X11(channel, session);
        if (result != SSH_OK)
            return result;
    }
    result = ssh_channel_request_shell(channel);
    if (result != SSH_OK)
        return result;
    signal(SIGWINCH, handle_winch);
    result = insert_item(channel, fileno(stdin), fileno(stdout), 1);
    if (result != 0)
    {
        return -1;
    }

    ssh_callbacks_init(&channel_cb);
    ssh_set_channel_callbacks(channel, &channel_cb);
    return result;
}

int interactive_shell_session(ssh_session session, ssh_channel channel)
{
    int result;
    event = ssh_event_new();
    if (event == NULL)
    {
        printf("Couldn't get a event\n");
        return -1;
    }

    result = ssh_event_add_fd(event, fileno(stdin), events,
                              copy_fd_to_channel_callback, channel);
    if (result != SSH_OK)
    {
        printf("Couldn't add an fd to the event\n");
        return -1;
    }

    result = ssh_event_add_session(event, session);
    if (result != SSH_OK)
    {
        printf("Couldn't add the session to the event\n");
        return -1;
    }

    do
    {
        if (ssh_event_dopoll(event, 1000) == SSH_ERROR)
        {
            printf("Error : %s\n", ssh_get_error(session));
        }
    } while (!ssh_channel_is_closed(channel));

    delete_item(channel);
    ssh_event_remove_fd(event, fileno(stdin));
    ssh_event_remove_session(event, session);
    ssh_event_free(event);

    return SSH_OK;
}

int connect_local_xsocket_path(const char *pathname)
{
    int sock, rc;
    struct sockaddr_un addr;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1)
    {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    memcpy(addr.sun_path + 1, pathname, sizeof(addr.sun_path) - 1);
    rc = connect(sock, (struct sockaddr *)&addr,
                 offsetof(struct sockaddr_un, sun_path) + 1 + strlen(pathname));
    if (rc == 0)
    {
        return sock;
    }
    close(sock);
    return -1;
}

int connect_local_xsocket(int display_number)
{
    char buf[1024] = {0};
    snprintf(buf, sizeof(buf), _PATH_UNIX_X, display_number);
    return connect_local_xsocket_path(buf);
}

void set_nodelay(int fd)
{
    int opt, rc;
    socklen_t optlen;

    optlen = sizeof(opt);

    rc = getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen);
    if (rc == -1)
    {
        return;
    }
    if (opt == 1)
    {
        return;
    }
    opt = 1;

    rc = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
}

int x11_connect_display(void)
{
    int display_number;
    char *display = NULL;
    char buf[1024], *cp = NULL;
    struct addrinfo hints, *ai = NULL, *aitop = NULL;
    char strport[NI_MAXSERV];
    int gaierr = 0, sock = 0;

    display = getenv("DISPLAY");

    if (display == 0)
    {
        return -1;
    }

    if (strncmp(display, "unix:", 5) == 0 || display[0] == ':')
    {
        if (sscanf(strrchr(display, ':') + 1, "%d", &display_number) != 1)
        {
            return -1;
        }

        sock = connect_local_xsocket(display_number);

        if (sock < 0)
        {
            return -1;
        }

        return sock;
    }
    strncpy(buf, display, sizeof(buf) - 1);
    cp = strchr(buf, ':');
    if (cp == 0)
    {
        return -1;
    }
    *cp = 0;
    if (sscanf(cp + 1, "%d", &display_number) != 1)
    {
        return -1;
    }
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(strport, sizeof(strport), "%u", 6000 + display_number);
    gaierr = getaddrinfo(buf, strport, &hints, &aitop);
    if (gaierr != 0)
    {
        return -1;
    }
    for (ai = aitop; ai; ai = ai->ai_next)
    {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock == -1)
        {
            continue;
        }
        if (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1)
        {
            close(sock);
            continue;
        }
        break;
    }
    freeaddrinfo(aitop);
    if (ai == 0)
    {
        return -1;
    }
    set_nodelay(sock);

    return sock;
}

int enable_X11(ssh_channel channel, ssh_session session)
{
    char *display = getenv("DISPLAY");
    char *proto = NULL, *cookie = NULL;
    int result;

    if (display)
    {
        ssh_callbacks_init(&cb);
        result = ssh_set_callbacks(session, &cb);
        if (result != SSH_OK)
        {
            return result;
        }

        result = x11_get_proto(display, &proto, &cookie);
        if (result != 0)
        {
            proto = NULL;
            cookie = NULL;
        }

        result = ssh_channel_request_x11(channel, 0, proto, cookie, 0);
        if (result != SSH_OK)
        {
            return result;
        }
    }
    return 0;
}
