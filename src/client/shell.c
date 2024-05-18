#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "shell.h"

ssh_channel general_channel;

void handle_winch(int sig)
{
    if (sig == SIGWINCH)
    {
        struct winsize ws;
        ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws);
        printf("Rows: %d, Cols: %d\n", ws.ws_row, ws.ws_col);
        ssh_channel_change_pty_size(general_channel, ws.ws_col, ws.ws_row);
    }
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

    if ((result = make_interactive_shell(channel) >= 0))
    {
        interactive_shell_session(session, channel);
    }

    tcsetattr(0, TCSANOW, &tty_params);

    ssh_channel_close(channel);
    ssh_channel_send_eof(channel);
    ssh_channel_free(channel);

    return result;
}

int make_interactive_shell(ssh_channel channel)
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

    result = ssh_channel_request_shell(channel);
    if (result != SSH_OK)
        return result;

    signal(SIGWINCH, handle_winch);
    return result;
}

int interactive_shell_session(ssh_session session, ssh_channel channel)
{
    char buffer[256];
    int nbytes, nwritten;

    while (ssh_channel_is_open(channel) &&
           !ssh_channel_is_eof(channel))
    {
        struct timeval timeout;
        ssh_channel in_channels[2], out_channels[2];
        fd_set fds;
        int maxfd;

        timeout.tv_sec = 30;
        timeout.tv_usec = 0;
        in_channels[0] = channel;
        in_channels[1] = NULL;
        FD_ZERO(&fds);
        FD_SET(0, &fds);
        FD_SET(ssh_get_fd(session), &fds);
        maxfd = ssh_get_fd(session) + 1;

        ssh_select(in_channels, out_channels, maxfd, &fds, &timeout);

        if (out_channels[0] != NULL)
        {
            nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
            if (nbytes < 0)
                return SSH_ERROR;
            if (nbytes > 0)
            {
                nwritten = write(1, buffer, nbytes);
                if (nwritten != nbytes)
                    return SSH_ERROR;
            }
        }

        if (FD_ISSET(0, &fds))
        {
            nbytes = read(0, buffer, sizeof(buffer));
            if (nbytes < 0)
                return SSH_ERROR;
            if (nbytes > 0)
            {
                nwritten = ssh_channel_write(channel, buffer, nbytes);
                if (nbytes != nwritten)
                    return SSH_ERROR;
            }
        }
    }

    return SSH_OK;
}