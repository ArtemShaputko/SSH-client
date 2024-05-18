#define _GNU_SOURCE
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "client.h"
#include "shell.h"
#include "auth.h"

#define JSON_PARSE_ERROR -5

int client_function(const cmd_options *opts)
{
    ssh_session general_session = create_session(opts);
    if (ssh_connect(general_session) != SSH_OK)
    {
        fprintf(stderr, "Error connecting to host: %s\n",
                ssh_get_error(general_session));
        ssh_free(general_session);
        exit(1);
    }

    if (verify_server(general_session) < 0)
    {
        ssh_disconnect(general_session);
        ssh_free(general_session);
        exit(1);
    }

    if (log_in(general_session) < 0)
    {
        ssh_disconnect(general_session);
        ssh_free(general_session);
        exit(1);
    }

    display_banner(general_session);

    if (shell_session(general_session) < 0)
    {
        ssh_disconnect(general_session);
        ssh_free(general_session);
        exit(1);
    }

    ssh_disconnect(general_session);
    ssh_free(general_session);
    return 0;
}

ssh_session create_session(const cmd_options *opts)
{
    ssh_session session = ssh_new();
    if (session == NULL)
    {
        fprintf(stderr, "Can`t create session\n");
        exit(1);
    }
    ssh_options_set(session, SSH_OPTIONS_HOST, opts->host_ip);
    ssh_options_set(session, SSH_OPTIONS_USER, opts->user_name);
    if (opts->port != 0)
    {
        ssh_options_set(session, SSH_OPTIONS_PORT_STR, opts->port);
    }
    if (opts->key_file != 0)
    {
    }

    return session;
}

int json_publickey_find(json_value *value, void *key)
{
    ssh_key *server_key = (ssh_key *)key;
    ssh_key known_key;
    json_value key_value, type_value;

    if (json_object_find_value(value, "key", &key_value) == 0)
    {
        if (key_value.type == JSON_STRING)
        {
            if (json_object_find_value(value, "type", &type_value) == 0)
            {
                if (type_value.type == JSON_STRING)
                {
                    if (ssh_pki_import_pubkey_base64(key_value.string,
                                                     ssh_key_type_from_name(type_value.string),
                                                     &known_key) == 0)
                    {
                        if (ssh_key_cmp(known_key, *server_key, SSH_KEY_CMP_PUBLIC) == 0)
                        {
                            if (ssh_key_type_from_name(type_value.string) == ssh_key_type(*server_key))
                            {
                                return 0;
                            }
                            return 1;
                        }
                    }
                }
            }
        }
    }
    return -1;
}

int json_is_server_known(ssh_session session, json_value *known_hosts)
{
    ssh_key server_key;
    json_value known_keys;
    int ret;
    char *host_name;
    if (ssh_get_server_publickey(session, &server_key) < 0)
    {
        return SSH_SERVER_ERROR;
    }
    if (known_hosts->type == JSON_NONE)
    {
        return SSH_SERVER_FILE_NOT_FOUND;
    }
    ssh_options_get(session, SSH_OPTIONS_HOST, &host_name);
    ret = json_object_find_value(known_hosts, host_name, &known_keys);
    switch (ret)
    {
    case -1:
        return JSON_PARSE_ERROR;
    case -2:
        return SSH_SERVER_NOT_KNOWN;
    default:
    {
        ret = json_array_data_exists(&known_keys, json_publickey_find, (void *)&server_key);
        switch (ret)
        {
        case 0:
            return SSH_SERVER_KNOWN_OK;
        case -1:
            return JSON_PARSE_ERROR;
        case -2:
            return SSH_SERVER_FOUND_OTHER;
        default:
            return SSH_SERVER_KNOWN_CHANGED;
        }
    }
    }
}

int verify_server(ssh_session session)
{
    size_t hash_len;
    ssh_key key;
    unsigned char *hash = NULL;
    enum ssh_publickey_hash_type type = SSH_PUBLICKEY_HASH_SHA256;
    json_value known_hosts = {0};
    printf("file: %s\n", known_hosts_file_full_path);
    if (parse_json_file(known_hosts_file_full_path, &known_hosts) < 0)
    {
        fprintf(stderr, "Cannot open file\n");
        return -1;
    }

    int state = json_is_server_known(session, &known_hosts);
    if (ssh_get_server_publickey(session, &key) < 0)
    {
        free_json_value(&known_hosts);
        return -1;
    }
    int ret = ssh_get_publickey_hash(key, type, &hash, &hash_len);
    ssh_key_free(key);
    if (ret < 0)
    {
        free_json_value(&known_hosts);
        return -1;
    }
    switch (state)
    {
    case JSON_PARSE_ERROR:
        fprintf(stderr, "Problems with parsing file\n");
        break;
    case SSH_SERVER_KNOWN_OK:
        break;

    case SSH_SERVER_KNOWN_CHANGED:
        fprintf(stderr, "Host key for server changed: it is now:\n");
        printf("Public key hash ");
        ssh_print_hash(type, hash, hash_len);
        printf("\n");
        fprintf(stderr, "For security reasons, connection will be stopped\n");
        free(hash);
        free_json_value(&known_hosts);
        return -1;

    case SSH_SERVER_FOUND_OTHER:
        fprintf(stderr, "The host key for this server was not found but an other"
                        "type of key exists.\n");
        fprintf(stderr, "An attacker might change the default server key to"
                        "confuse your client into thinking the key does not exist\n");
        free_json_value(&known_hosts);
        free(hash);
        return -1;

    case SSH_SERVER_FILE_NOT_FOUND:
        fprintf(stderr, "Could not find known host file.\n");
        fprintf(stderr, "If you accept the host key here, the file will be"
                        "automatically created.\n");
        if (write_server_hash(session, hash, hash_len, &known_hosts) < 0)
        {
            free_json_value(&known_hosts);
            free(hash);
            return -1;
        }
        break;

    case SSH_SERVER_NOT_KNOWN:
        if (write_server_hash(session, hash, hash_len, &known_hosts) < 0)
        {
            free_json_value(&known_hosts);
            free(hash);
            return -1;
        }
        break;

    case SSH_SERVER_ERROR:
        fprintf(stderr, "Error %s", ssh_get_error(session));
        free(hash);
        free_json_value(&known_hosts);
        return -1;
    }
    free(hash);
    free_json_value(&known_hosts);
    return 0;
}

int json_create_key_object(ssh_session session, json_value *object)
{
    ssh_key key;
    if (ssh_get_server_publickey(session, &key) < 0)
    {
        fprintf(stderr, "Cannot get key\n");
        return -1;
    }
    object->type = JSON_OBJECT;
    object->object = calloc(3, sizeof(json_pair));
    object->object[0].key = calloc(5, sizeof(char));
    object->object[1].key = calloc(4, sizeof(char));
    strcpy(object->object[0].key, "type");
    strcpy(object->object[1].key, "key");
    object->object[0].value.type = JSON_STRING;
    object->object[1].value.type = JSON_STRING;
    object->object[0].value.string = calloc(20, sizeof(char *));
    strcpy(object->object[0].value.string, ssh_key_type_to_char(ssh_key_type(key)));
    if (ssh_pki_export_pubkey_base64(key, &object->object[1].value.string))
    {
        fprintf(stderr, "Cannot export key\n");
        return -1;
    }
    printf("key : %s\n", object->object[0].value.string);
    printf("value : %s\n", object->object[1].value.string);
    return 0;
}

int json_array_add_ssh_key(ssh_session session, json_value *array)
{
    int res = 0;
    if (array->type == JSON_NONE)
    {
        array->array = calloc(2, sizeof(json_value));
        array->type = JSON_ARRAY;
    }
    else
    {
        while (array[res].type != JSON_NONE)
            res++;
    }
    if (json_create_key_object(session, &array->array[0]))
    {
        return -1;
    }
    return 0;
}

int json_add_ssh_key(ssh_session session, json_value *value)
{
    int size = 0, res;
    char *host;
    json_value place;
    if (ssh_options_get(session, SSH_OPTIONS_HOST, &host) < 0)
    {
        fprintf(stderr, "Cannot get host\n");
        return -1;
    }
    if (value->type == JSON_NONE)
    {
        value->object = calloc(2, sizeof(json_pair));
        value->type = JSON_OBJECT;
    }
    else
    {
        res = json_object_find_value(value, host, &place);
        switch (res)
        {
        case 0:
            res = json_array_add_ssh_key(session, &place);
            free(host);
            return res;
        case -2:
            for (; value->object[size].key != NULL; size++)
                ;
            value->object = realloc(value->object, (size + 2) * sizeof(json_pair));
            break;
        case -1:
            free(host);
            fprintf(stderr, "Error while finding host\n");
            return -1;

        default:
            return -1;
        }
    }
    value->object[size].key = host;
    res = json_array_add_ssh_key(session, &value->object[size].value);
    return res;
}

int write_server_hash(ssh_session session,
                      const unsigned char *hash,
                      size_t hash_len,
                      json_value *value)
{
    char buf[10];
    char *hexa = ssh_get_hexa(hash, hash_len);
    fprintf(stderr, "The server is unknown. Do you trust the host key?\n");
    fprintf(stderr, "Public key hash: %s\n", hexa);
    fprintf(stdout, "[Yes/No]: ");
    free(hexa);
    if (fgets(buf, sizeof(buf), stdin) == NULL)
    {
        return -1;
    }
    if (strncasecmp(buf, "yes", 3) != 0)
    {
        return -1;
    }

    if (json_add_ssh_key(session, value))
    {
        return -1;
    }
    if (write_json_to_file(known_hosts_file_full_path, value))
    {
        fprintf(stderr, "Error while writing\n");
    }
    return 0;
}