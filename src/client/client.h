#ifndef CLIENT_H
#define CLIENT_H

#include <libssh/libssh.h>
#include <stddef.h>

#include "../master/utils.h"

ssh_session create_session(const cmd_options *opts);
int client_function(const cmd_options *opts);
int verify_server(ssh_session session);
int write_server_hash(ssh_session session, const unsigned char *hash, size_t hash_len, json_value *value);
int log_in_pubkey(ssh_session session);
int log_in_kbdint(ssh_session session);
int log_in_password(ssh_session session);
int log_in(ssh_session session);
void display_banner(ssh_session session);
int json_is_server_known(ssh_session session, json_value *known_hosts);
int json_publickey_find(json_value *value, void *key);
int json_create_key_object(ssh_session session, json_value *object);
int json_array_add_ssh_key(ssh_session session, json_value *array);
int json_add_ssh_key(ssh_session session, json_value *value);

#endif