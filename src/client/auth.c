#define _GNU_SOURCE
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "auth.h"

int log_in_pubkey(ssh_session session)
{
    int auth_result;

    auth_result = ssh_userauth_publickey_auto(session, NULL, NULL);

    if (auth_result != SSH_AUTH_SUCCESS)
    {
        fprintf(stderr, "%s\n",
                ssh_get_error(session));
        return SSH_AUTH_ERROR;
    }

    return auth_result;
}

int log_in_password(ssh_session session)
{
    char *password;
    int auth_result;

    password = getpass("Enter password: ");
    auth_result = ssh_userauth_password(session, NULL, password);
    if (auth_result != SSH_AUTH_SUCCESS)
    {
        fprintf(stderr, "%s\n",
                ssh_get_error(session));
        return SSH_AUTH_ERROR;
    }

    return auth_result;
}

int log_in_kbdint(ssh_session session)
{
    int auth_result;

    auth_result = ssh_userauth_kbdint(session, NULL, NULL);
    while (auth_result == SSH_AUTH_INFO)
    {
        const char *name, *instruction;
        int nprompts, iprompt;

        name = ssh_userauth_kbdint_getname(session);
        instruction = ssh_userauth_kbdint_getinstruction(session);
        nprompts = ssh_userauth_kbdint_getnprompts(session);

        if (strlen(name) > 0)
            printf("%s\n", name);
        if (strlen(instruction) > 0)
            printf("%s\n", instruction);
        for (iprompt = 0; iprompt < nprompts; iprompt++)
        {
            const char *prompt;
            char echo;

            prompt = ssh_userauth_kbdint_getprompt(session, iprompt, &echo);
            if (echo)
            {
                char buffer[128], *ptr;

                printf("%s", prompt);
                if (fgets(buffer, sizeof(buffer), stdin) == NULL)
                    return SSH_AUTH_ERROR;
                buffer[sizeof(buffer) - 1] = '\0';
                if ((ptr = strchr(buffer, '\n')) != NULL)
                    *ptr = '\0';
                if (ssh_userauth_kbdint_setanswer(session, iprompt, buffer) < 0)
                    return SSH_AUTH_ERROR;
                memset(buffer, 0, strlen(buffer));
            }
            else
            {
                char *ptr;

                ptr = getpass(prompt);
                if (ssh_userauth_kbdint_setanswer(session, iprompt, ptr) < 0)
                    return SSH_AUTH_ERROR;
            }
        }
        auth_result = ssh_userauth_kbdint(session, NULL, NULL);
    }
    return auth_result;
}

int log_in(ssh_session session)
{
    int method, auth_result;

    auth_result = ssh_userauth_none(session, NULL);
    if (auth_result == SSH_AUTH_SUCCESS || auth_result == SSH_AUTH_ERROR)
    {
        return auth_result;
    }

    method = ssh_userauth_list(session, NULL);

    if (method & SSH_AUTH_METHOD_NONE)
    {
        auth_result = ssh_userauth_none(session, NULL);
        if (auth_result == SSH_AUTH_SUCCESS)
            return auth_result;
    }
    if (method & SSH_AUTH_METHOD_PUBLICKEY)
    {
        auth_result = log_in_pubkey(session);
        if (auth_result == SSH_AUTH_SUCCESS)
            return auth_result;
    }
    if (method & SSH_AUTH_METHOD_INTERACTIVE)
    {
        auth_result = log_in_kbdint(session);
        if (auth_result == SSH_AUTH_SUCCESS)
            return auth_result;
    }
    if (method & SSH_AUTH_METHOD_PASSWORD)
    {
        auth_result = log_in_password(session);
        if (auth_result == SSH_AUTH_SUCCESS)
            return auth_result;
    }
    return SSH_AUTH_ERROR;
}

void display_banner(ssh_session session)
{
    char *banner;

    banner = ssh_get_issue_banner(session);
    if (banner)
    {
        printf("%s\n", banner);
        free(banner);
    }
}