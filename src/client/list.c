#include "list.h"

#include <pthread.h>
#include <stdlib.h>

node_t *node = NULL;

pthread_mutex_t mutex;

int insert_item(ssh_channel channel, int fd_in, int fd_out,
                int protected)
{
    node_t *node_iterator = NULL, *new = NULL;

    pthread_mutex_lock(&mutex);

    if (node == NULL)
    {
        node = (node_t *)calloc(1, sizeof(node_t));
        if (node == NULL)
        {
            pthread_mutex_unlock(&mutex);
            return -1;
        }
        node->channel = channel;
        node->fd_in = fd_in;
        node->fd_out = fd_out;
        node->prted = protected;
        node->next = NULL;
    }
    else
    {
        node_iterator = node;
        while (node_iterator->next != NULL)
        {
            node_iterator = node_iterator->next;
        }
        /* Create the new node */
        new = (node_t *)malloc(sizeof(node_t));
        if (new == NULL)
        {
            pthread_mutex_unlock(&mutex);
            return -1;
        }
        new->channel = channel;
        new->fd_in = fd_in;
        new->fd_out = fd_out;
        new->prted = protected;
        new->next = NULL;
        node_iterator->next = new;
    }

    pthread_mutex_unlock(&mutex);
    return 0;
}

void delete_item(ssh_channel channel)
{
    node_t *current = NULL, *previous = NULL;

    pthread_mutex_lock(&mutex);

    for (current = node; current; previous = current, current = current->next)
    {
        if (current->channel != channel)
        {
            continue;
        }

        if (previous == NULL)
        {
            node = current->next;
        }
        else
        {
            previous->next = current->next;
        }

        free(current);
        pthread_mutex_unlock(&mutex);
        return;
    }

    pthread_mutex_unlock(&mutex);
}

node_t *search_item(ssh_channel channel)
{
    node_t *current = NULL;

    pthread_mutex_lock(&mutex);

    current = node;
    while (current != NULL)
    {
        if (current->channel == channel)
        {
            pthread_mutex_unlock(&mutex);
            return current;
        }
        else
        {
            current = current->next;
        }
    }

    pthread_mutex_unlock(&mutex);

    return NULL;
}