/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "pch.h"
#include "log.h"

int LOG_LEVEL = 2;
// When you are using pre-compiled headers, this source file is necessary for compilation to succeed.
void WriteLog(
    int level,
    int line,
    const char *file,
    const char *function,
    const char *format,
    ...)
{
    if (level < LOG_LEVEL)
    {
        return;
    }

    FILE *filepntr = 0;
    //fopen("/var/log/nginx/akv_error.log", "aw+");

    va_list arglist;
    va_start(arglist, format);
    const char *shortFilename = file;
    for (int i = 0; i <= 1; i++)
    {
        const char *p = strrchr(file, i == 0 ? '/' : '\\');
        if (p != NULL)
        {
            p++;
            if (*p != '\0' && p > shortFilename)
            {
                shortFilename = p;
            }
        }
    }
    fprintf(stderr, "[%c] %s %s(%d) ",
           level == LogLevel_Error ? 'e' : level == LogLevel_Info ? 'i'
                                                                  : 'd',
           function,
           shortFilename,
           line);
    vfprintf(stderr, format, arglist);
    va_end(arglist);
    fprintf(stderr, "\n");
}

int crypto_op_enqueue(volatile crypto_op_queue *queue,
                               crypto_op_data *item)
{
    if (queue == NULL || item == NULL) {
        log_debug("Queue NULL\n");
        return 0;
    }
    log_debug("In enqueue before lock\n");
    pthread_mutex_lock(&queue->crypto_op_queue_mutex);
    log_debug("In enqueue after lock\n");
    if (queue->num_items == 0) {
        queue->tail = item;
        queue->head = item;
    } else {
        queue->tail->next = item;
        queue->tail = item;
    }
    queue->tail->next = NULL;
    queue->num_items++;
    log_debug("Enqueued item %p, total items in queue %d queue ptr %p queue head %p tail %p\n", item, queue->num_items, queue, queue->head, queue->tail);
    pthread_mutex_unlock(&queue->crypto_op_queue_mutex);

    pthread_mutex_lock(&txt_mutex);
    log_debug("In enqueue after unlock queue %p queue head %p tail %p txt %d txtptr %p\n", queue, queue->head, queue->tail, *txt, txt);
    pthread_mutex_unlock(&txt_mutex);
    return 1;
}

crypto_op_data * crypto_op_dequeue(volatile crypto_op_queue *queue)
{
    crypto_op_data *item = NULL;

    if (queue == NULL)
        return NULL;

    pthread_mutex_lock(&queue->crypto_op_queue_mutex);

    if (queue->head == NULL) {
        pthread_mutex_unlock(&queue->crypto_op_queue_mutex);
        log_debug("In dequeue head null, queue %p num items %d queue tail %p\n", queue, queue->num_items, queue->tail);
        return NULL;
    }
    log_debug("In dequeue after null checks\n");
    item = queue->head;
    queue->head = item->next;
    queue->num_items--;

    if (queue->num_items == 0)
        queue->tail = NULL;
    log_debug("Dequeued item %p, total items in queue %d\n", item, queue->num_items);
    pthread_mutex_unlock(&queue->crypto_op_queue_mutex);
    return item;
}

int crypto_op_queue_get_size(volatile crypto_op_queue *queue)
{
    if (queue == NULL)
        return 0;

    return queue->num_items;
}

crypto_op_queue * crypto_op_queue_create()
{
    crypto_op_queue *queue = NULL;

    queue = OPENSSL_zalloc(sizeof(crypto_op_queue));
    if (queue == NULL)
        return NULL;

    log_debug("Queue Created %p\n", queue);

    pthread_mutex_init(&queue->crypto_op_queue_mutex, NULL);
    pthread_mutex_lock(&queue->crypto_op_queue_mutex);
    queue->head = NULL;
    queue->tail = NULL;
    queue->num_items = 0;
    pthread_mutex_unlock(&queue->crypto_op_queue_mutex);
    return queue;
}
