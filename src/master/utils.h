#ifndef UTILS_H
#define UTILS_H

#include <limits.h>
#include <stddef.h>

#define KNOWN_HOSTS_FILE ".sc/known_hosts"

extern char known_hosts_file_full_path[PATH_MAX];

typedef enum
{
    CLIENT,
    SERVER
} host_type;

typedef enum
{
    JSON_NONE,
    JSON_ARRAY,
    JSON_OBJECT,
    JSON_LONG,
    JSON_STRING,
    JSON_BOOL,
    JSON_DOUBLE,
    JSON_NULL
} json_type;

typedef struct cmd_options_type cmd_options;
typedef struct json_value_type json_value;
typedef struct json_pair_type json_pair;

/* Должна возвращать 0, если найден, -1 если нет и >0 - пользовательские варианты*/
typedef int(json_find)(json_value *v, void *user_data);

// Возвращает -1, если ошибка, -2 если не найден и >= 0 при совпадении
int json_array_data_exists(const json_value *array, json_find *cmp, void *user_data);
// Возвращает -1, если ошибка, -2 если не найден и >= 0, если ключ найден и записывает в object значение
int json_object_find_value(const json_value *object, const char *key, json_value *value);

int parse_json_file(const char *filename, json_value *result);
const char *skip_whtespace(const char *str, size_t *len);
const char *parse_json_value(const char *str, size_t *len, json_value *value);
const char *parse_json_number(const char *str, size_t *len, json_value *value);
const char *parse_json_string(const char *str, size_t *len, json_value *value);
const char *parse_json_default(const char *str, size_t *len, json_value *value);
const char *parse_json_array(const char *str, size_t *len, json_value *value);
const char *parse_json_pair(const char *str, size_t *len, json_pair *pair);
const char *parse_json_object(const char *str, size_t *len, json_value *value);

void free_json_value(json_value *value);

int write_json_to_file(const char *filename, json_value *value);
int write_json_value_to_file(int fd, json_value *value, int level);
int write_json_bool_to_file(int fd, json_value *value);
int write_json_null_to_file(int fd);
int write_json_double_to_file(int fd, json_value *value);
int write_json_long_to_file(int fd, json_value *value);
int write_json_string_to_file(int fd, json_value *value);
int write_json_array_to_file(int fd, json_value *value, int level);
int write_json_object_to_file(int fd, json_value *value, int level);

struct cmd_options_type
{
    char host_ip[20];
    char user_name[20];
    char *port;
    char *key_file;
    int x11enable;
};

struct json_value_type
{
    json_type type;
    union
    {
        char *string;
        long number_long;
        int boolean;
        double number_double;
        json_pair *object;
        json_value *array;
    };
};

struct json_pair_type
{
    char *key;
    json_value value;
};

#endif