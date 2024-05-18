#define _GNU_SOURCE
#define _DEFAULT_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <ctype.h>
#include <sys/param.h>
#include <errno.h>

#include "utils.h"

int json_array_data_exists(const json_value *array, json_find *cmp, void *user_data)
{
    int cmp_res;
    if (array->type != JSON_ARRAY)
    {
        return -1;
    }

    for (int i = 0; array->array[i].type != JSON_NONE; i++)
    {
        if ((cmp_res = cmp(&array->array[i], user_data)) != -1)
        {
            return cmp_res;
        }
    }
    return -2;
}

int json_object_find_value(const json_value *object, const char *key, json_value *value)
{
    if (object->type != JSON_OBJECT)
    {
        return -1;
    }

    for (int i = 0; object->object[i].key != NULL; i++)
    {
        if (strcmp(key, object->object[i].key) == 0)
        {
            *value = object->object[i].value;
            return 0;
        }
    }
    return -2;
}

int parse_json_file(const char *filename, json_value *result)
{
    char *content;
    int fd = open(filename, O_RDWR | O_CREAT, 0666);
    if (fd < 0)
    {
        perror("open:");
        return -1;
    }
    struct stat file_stat;
    if (fstat(fd, &file_stat) < 0)
    {
        close(fd);
        return -1;
    }
    size_t size = file_stat.st_size;
    if (size == 0)
    {
        result->type = JSON_NONE;
        close(fd);
        return 0;
    }
    if (ftruncate(fd, size) < 0)
    {
        perror("ftruncate");
        close(fd);
        return -1;
    }
    if ((content = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == (void *)(-1))
    {
        close(fd);
        return -1;
    }
    close(fd);

    if (parse_json_value(content, &size, result) == NULL)
    {
        munmap(content, size);
        return -1;
    }

    munmap(content, size);
    return 0;
}

const char *parse_json_value(const char *str, size_t *len, json_value *value)
{
    if (*len > 0)
    {
        if ((str = skip_whtespace(str, len)) != NULL)
        {
            if (*str == '\"')
            {
                str = parse_json_string(str, len, value);
            }
            else if (*str == '[')
            {
                str = parse_json_array(str, len, value);
            }
            else if (*str == '{')
            {
                str = parse_json_object(str, len, value);
            }
            else if (*str == 't' || *str == 'f' || *str == 'n')
            {
                str = parse_json_default(str, len, value);
            }
            else if (isdigit(*str) || *str == '-')
            {
                str = parse_json_number(str, len, value);
            }
            if (str == NULL)
            {
                return NULL;
            }
            if ((str = skip_whtespace(str, len)) != NULL)
            {
                return str;
            }
        }
    }
    return NULL;
}

const char *skip_whtespace(const char *str, size_t *len)
{
    int i = 0;
    char c;
    while (*len > 0)
    {
        c = str[i];
        if (c != 32 && c != 10 && c != 13 && c != 9 && c != 11)
        {
            return &str[i];
        }
        i++;
        (*len)--;
    }
    return &str[i];
}

const char *parse_json_string(const char *str, size_t *len, json_value *value)
{
    if (*len <= 1)
    {
        return NULL;
    }
    char c;
    value->type = JSON_STRING;
    int buf_len = 10, buf_pos = 0;
    char *buffer = calloc(buf_len, sizeof(char));
    str = str + 1;
    for (int i = 0; *len > 0 && str[i] != '\0'; i++, (*len)--, buf_pos++)
    {
        if (buf_pos >= buf_len)
        {
            buf_len *= 2;
            buffer = realloc(buffer, buf_len * sizeof(char));
        }
        c = str[i];
        if (c == '\\')
        {
            if (*len <= 0)
            {
                free(buffer);
                return NULL;
            }
            i++;
            (*len)--;
        }
        else if (c == '\"')
        {
            if (*len <= 0)
            {
                free(buffer);
                return NULL;
            }
            value->string = realloc(buffer, (buf_pos + 1) * sizeof(char));
            value->string[buf_pos] = '\0';
            return &str[i + 1];
        }
        buffer[buf_pos] = str[i];
    }
    free(buffer);
    return NULL;
}

const char *parse_json_number(const char *str, size_t *len, json_value *value)
{
    char *str_lend, *str_dend;
    long lbuf;
    double dbuf;
    lbuf = strtol(str, &str_lend, 10);
    dbuf = strtod(str, &str_dend);
    if (str_dend - str > str_lend - str)
    {
        value->type = JSON_DOUBLE;
        value->number_double = dbuf;
    }
    else
    {
        value->type = JSON_LONG;
        value->number_long = lbuf;
    }
    *len -= str_dend - str;
    return str_dend;
}

const char *parse_json_default(const char *str, size_t *len, json_value *value)
{
    if (strncmp(str, "null", 4) == 0)
    {
        value->type = JSON_NULL;
        *len -= 4;
        return str + 4;
    }
    value->type = JSON_BOOL;
    if (strncmp(str, "true", 4) == 0)
    {
        value->boolean = 1;
        *len -= 4;
        return str + 4;
    }
    if (strncmp(str, "false", 5) == 0)
    {
        value->boolean = 0;
        *len -= 5;
        return str + 5;
    }
    return NULL;
}

const char *parse_json_array(const char *str, size_t *len, json_value *value)
{
    value->type = JSON_ARRAY;
    int size = 5;
    json_value *array = calloc(size, sizeof(json_value));
    int i = 0;
    str++;
    while (*str != ']')
    {
        if (i >= size)
        {
            size *= 2;
            array = realloc(array, size);
        }
        str = parse_json_value(str, len, &array[i]);
        if (str == NULL || *len <= 0 || (*str != ',' && *str != ']'))
        {
            for (int j = 0; j < i + 1; j++)
            {
                free_json_value(&array[j]);
            }
            free(array);
            return NULL;
        }
        if (*str == ',')
        {
            str++;
        }
        i++;
    }
    array = realloc(array, (i + 1) * sizeof(json_value));
    array[i].type = JSON_NONE;
    value->array = array;
    return ++str;
}

const char *parse_json_object(const char *str, size_t *len, json_value *value)
{
    value->type = JSON_OBJECT;
    int size = 5;
    json_pair *object = calloc(size, sizeof(json_pair));
    str++;
    int i = 0;
    while (*str != '}')
    {
        if (i >= size)
        {
            size *= 2;
            object = realloc(object, size);
        }
        str = parse_json_pair(str, len, &object[i]);
        if (str == NULL || *len <= 0 || (*str != ',' && *str != '}'))
        {
            int val = str == NULL ? i : i + 1;
            for (int j = 0; j < val; j++)
            {
                free_json_value(&object[j].value);
                free(object[j].key);
            }
            free(object);
            return NULL;
        }
        if (*str == ',')
        {
            str++;
        }
        i++;
    }
    object = realloc(object, (i + 1) * sizeof(json_pair));
    object[i].value.type = JSON_NONE;
    value->object = object;
    return ++str;
}

const char *parse_json_pair(const char *str, size_t *len, json_pair *pair)
{
    json_value buf;
    if ((str = skip_whtespace(str, len)) != NULL)
    {
        if ((str = parse_json_string(str, len, &buf)) != NULL)
        {
            pair->key = buf.string;
            if ((str = skip_whtespace(str, len)) != NULL)
            {
                if (*str == ':')
                {
                    str++;
                    str = parse_json_value(str, len, &pair->value);
                    return str;
                }
            }
        }
    }
    return NULL;
}

void free_json_value(json_value *value)
{
    if (value->type == JSON_STRING)
    {
        free(value->string);
    }
    if (value->type == JSON_ARRAY)
    {
        for (int i = 0; value->array[i].type != JSON_NONE; i++)
        {
            free_json_value(&value->array[i]);
        }
        free(value->array);
    }
    if (value->type == JSON_OBJECT)
    {
        for (int i = 0; value->object[i].value.type != JSON_NONE; i++)
        {
            free_json_value(&value->object[i].value);
            free(value->object[i].key);
        }
        free(value->object);
    }
}

int write_json_to_file(const char *filename, json_value *value)
{
    int fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0666);
    int level = 0;
    int res = write_json_value_to_file(fd, value, level);
    close(fd);
    return res;
}

int write_json_value_to_file(int fd, json_value *value, int level)
{
    switch (value->type)
    {
    case JSON_ARRAY:
        return write_json_array_to_file(fd, value, level);
    case JSON_BOOL:
        return write_json_bool_to_file(fd, value);
    case JSON_DOUBLE:
        return write_json_double_to_file(fd, value);
    case JSON_LONG:
        return write_json_long_to_file(fd, value);
    case JSON_NONE:
        return 0;
    case JSON_NULL:
        return write_json_null_to_file(fd);
    case JSON_OBJECT:
        return write_json_object_to_file(fd, value, level);
    case JSON_STRING:
        return write_json_string_to_file(fd, value);
    default:
        return -1;
    }
    return 0;
}

int write_json_bool_to_file(int fd, json_value *value)
{
    if (value->boolean == 1)
    {
        if (write(fd, "true", 4) < 4)
        {
            return -1;
        }
    }
    else if (value->boolean == 0)
    {
        if (write(fd, "false", 5) < 5)
        {
            return -1;
        }
    }
    return 0;
}

int write_json_null_to_file(int fd)
{
    if (write(fd, "null", 4) < 4)
    {
        return -1;
    }
    return 0;
}

int write_json_double_to_file(int fd, json_value *value)
{
    char str_num[32] = {0};
    snprintf(str_num, 32, "%lf", value->number_double);
    if (write(fd, str_num, strlen(str_num)) < (ssize_t)strlen(str_num))
    {
        return -1;
    }
    return 0;
}

int write_json_long_to_file(int fd, json_value *value)
{
    char str_num[32] = {0};
    snprintf(str_num, 32, "%ld", value->number_long);
    if (write(fd, str_num, strlen(str_num)) < (ssize_t)strlen(str_num))
    {
        return -1;
    }
    return 0;
}

int write_json_string_to_file(int fd, json_value *value)
{
    printf("str: %s\n", value->string);
    char c;
    write(fd, "\"", 1);
    for (int i = 0; value->string[i] != '\0'; i++)
    {
        c = value->string[i];
        if (c == 32 || c == 10 || c == 13 || c == 9 || c == 11)
        {
            write(fd, "\\", 1);
        }
        write(fd, &c, 1);
    }
    if (write(fd, "\"", 1) < 1)
    {
        return -1;
    }
    return 0;
}

int write_json_array_to_file(int fd, json_value *value, int level)
{
    write(fd, "[\n", 2);
    for (int i = 0; value->array[i].type != JSON_NONE; i++)
    {
        for (int i = 0; i < level + 1; i++)
        {
            write(fd, "    ", 4);
        }
        if (write_json_value_to_file(fd, &value->array[i], level + 1) < 0)
        {
            return -1;
        }
        if (value->array[i + 1].type != JSON_NONE)
        {
            write(fd, ",", 1);
        }
        write(fd, "\n", 1);
    }
    for (int i = 0; i < level; i++)
    {
        write(fd, "    ", 4);
    }
    if (write(fd, "]", 1) < 1)
    {
        return -1;
    }
    return 0;
}

int write_json_object_to_file(int fd, json_value *value, int level)
{
    json_value key_buf;
    key_buf.type = JSON_STRING;
    write(fd, "{\n", 2);
    for (int i = 0; value->object[i].key != NULL; i++)
    {
        for (int i = 0; i < level + 1; i++)
        {
            write(fd, "    ", 4);
        }
        key_buf.string = value->object[i].key;
        if (write_json_string_to_file(fd, &key_buf) < 0)
        {
            return -1;
        }
        write(fd, ": ", 2);
        if (write_json_value_to_file(fd, &value->object[i].value, level + 1) < 0)
        {
            return -1;
        }
        if (value->object[i + 1].key != NULL)
        {
            write(fd, ",", 1);
        }
        write(fd, "\n", 1);
    }
    for (int i = 0; i < level; i++)
    {
        write(fd, "    ", 4);
    }
    if (write(fd, "}", 1) < 1)
    {
        return -1;
    }
    return 0;
}