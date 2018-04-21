/*
 * Copyright (c) 2013, Mathias Brossard <mathias@brossard.org>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file threadpool.c
 * @brief Threadpool implementation file
 */

//#define _POSIX_C_SOURCE
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <zconf.h>

#include "threadpool.h"



typedef enum {
    immediate_shutdown = 1,
    graceful_shutdown  = 2
} threadpool_shutdown_t;

/**
 *  @struct threadpool_task
 *  @brief the work struct
 *
 *  @var function Pointer to the function that will perform the task.
 *  @var argument Argument to be passed to the function.
 */

typedef struct {
    void (*function)(void *);
    void *argument;
} threadpool_task_t;


struct threadpool_t {
    pthread_mutex_t lock;
    pthread_mutex_t busy_thrcount_mutex;
    pthread_cond_t queue_not_empty;
    pthread_cond_t queue_not_full;  // TODO not used
    pthread_t *threads;             // 保存线程 ID 的数组
    pthread_t *manager_thread;      // 管理线程
    threadpool_task_t *queue;       // 任务队列：环形的
    int thread_count;               // 初始的线程数量
    int max_thread_count;           // 最大线程数量
    int busy_thread_count;          // 正在工作的线程数量
    int wait_exit_thread_count;     // 等待退出的线程数量
    int queue_size;                 // 任务队列长度
    int max_queue_size;             // 最大任务队列长度
    int head;
    int tail;
    int count;                      // 队列上 等待 中的任务数量
    int shutdown;
    int started_n;                  // 已启动的线程数量，关闭线程池时需要检测这个量
};


int threadpool_free(threadpool_t *pool);

threadpool_t *threadpool_create(int thread_count, int queue_size, int flags)
{
    threadpool_t *pool;
    int i;

    /* TODO: we should check if the value is too large or negative */
    do {
        if ((pool = (threadpool_t *) malloc(sizeof(threadpool_t))) == NULL) {
//            goto err;
            break;
        }

        /* Initialize */
        pool->thread_count = 0;
        pool->queue_size = queue_size;
        pool->head = pool->tail = pool->count = 0;
        pool->shutdown = pool->started_n = 0;
        pool->busy_thread_count = 0;

        /* Allocate thread and task queue */
        pool->threads = (pthread_t *) malloc(sizeof(pthread_t) * thread_count);
        pool->queue = (threadpool_task_t *) malloc
                (sizeof(threadpool_task_t) * queue_size);

        /* Initialize mutex and condition variable */
        if ((pthread_mutex_init(&(pool->lock), NULL) != 0) ||
            (pthread_cond_init(&(pool->queue_not_empty), NULL) != 0) ||
//            (pthread_cond_init(&(pool->queue_not_full), NULL) != 0) ||
            (pool->threads == NULL) ||
            (pool->queue == NULL)) {
//            goto err;
            break;
        }

        /* Start worker threads */
        sigset_t oldset;
        sigset_t newset;
        sigemptyset(&newset);   /* Clear all signals from SET.  */
        sigaddset(&newset, SIGTERM);    // 终止
        sigaddset(&newset, SIGINT);     // 终端中断符 Delete, Ctrl+C
        sigaddset(&newset, SIGHUP);     // 连接断开
        sigaddset(&newset, SIGQUIT);    // 终端退出符
        pthread_sigmask(SIG_BLOCK, &newset, &oldset);

        for (i = 0; i < thread_count; i++) {
            if (pthread_create(&(pool->threads[i]), NULL,
                               threadpool_thread, (void *) pool) != 0) {
                threadpool_destroy(pool, 0);
                return NULL;
            }
            pool->thread_count++;
            pool->started_n++;
        }
        if (pthread_create(&(pool->manager_thread), NULL,
                           threadpool_manager, (void *) pool) != 0) {
            threadpool_destroy(pool, 0);
            return NULL;
        }
        pthread_sigmask(SIG_SETMASK, &oldset, NULL);
        return pool;
    }while(0);

    if(pool) {
       threadpool_free(pool);
    }
    return NULL;
}

int threadpool_add(threadpool_t *pool, void (*function)(void *),
                   void *argument, int flags)
{
    int err = 0;
    int next;

    if(pool == NULL || function == NULL) {
        return threadpool_invalid;
    }

    if(pthread_mutex_lock(&(pool->lock)) != 0) {
        return threadpool_lock_failure;
    }

    next = pool->tail + 1;
    next = (next == pool->queue_size) ? 0 : next;

    do {
        /* 任务队列满，等待管理线程扩容 */
//        while (pool->count == pool->queue_size) {
//            pthread_cond_wait(&(pool->queue_not_full), &(pool->lock));
//        }


        if(pool->count == pool->queue_size) {
//            err = threadpool_queue_full;
//            break;
            pool->queue_size ++;
        }

        /* Are we shutting down ? */
        if(pool->shutdown) {
            err = threadpool_shutdown;
            break;
        }

        /* Add task to queue */
        pool->queue[pool->tail].function = function;
        pool->queue[pool->tail].argument = argument;
        pool->tail = next;
        pool->count += 1;

        /* pthread_cond_broadcast */
        if(pthread_cond_signal(&(pool->queue_not_empty)) != 0) {
            err = threadpool_lock_failure;
            break;
        }
    } while(0);

    if(pthread_mutex_unlock(&pool->lock) != 0) {
        err = threadpool_lock_failure;
    }

    return err;
}

int threadpool_destroy(threadpool_t *pool, int flags)
{
    int i, err = 0;

    if(pool == NULL) {
        return threadpool_invalid;
    }

    if(pthread_mutex_lock(&(pool->lock)) != 0) {
        return threadpool_lock_failure;
    }

    do {
        /* Already shutting down */
        if(pool->shutdown) {
            err = threadpool_shutdown;
            break;
        }

        pool->shutdown = (flags & threadpool_graceful) ?
            graceful_shutdown : immediate_shutdown;

        /* Wake up all worker threads */
        if((pthread_cond_broadcast(&(pool->queue_not_empty)) != 0) ||
           (pthread_mutex_unlock(&(pool->lock)) != 0)) {
            err = threadpool_lock_failure;
            break;
        }

        /* Join all worker thread */
        for(i = 0; i < pool->thread_count; i++) {
            if(pthread_join(pool->threads[i], NULL) != 0) {
                err = threadpool_thread_failure;
            }
        }
    } while(0);

    /* Only if everything went well do we deallocate the pool */
    if(!err) {
        threadpool_free(pool);
    }
    return err;
}

int threadpool_free(threadpool_t *pool)
{
    if(pool == NULL || pool->started_n > 0) {
        return -1;
    }

    /* Did we manage to allocate ? */
    if(pool->threads) {
        free(pool->threads);
        free(pool->queue);

        /* Because we allocate pool->threads after initializing the
           mutex and condition variable, we're sure they're
           initialized. Let's lock the mutex just in case. */
        pthread_mutex_lock(&(pool->lock));
        pthread_mutex_destroy(&(pool->lock));
        pthread_cond_destroy(&(pool->queue_not_empty));
    }
    free(pool);
    return 0;
}

/**
 * 管理线程，当前用于动态扩容
 * @param threadpool
 * @return
 */
static void *threadpool_manager(void *threadpool)
{
    threadpool_t *pool = (threadpool_t *)threadpool;
    while(!pool->shutdown) {
        sleep(10);  // 每 10s 检测一次

        pthread_mutex_lock(&(pool->lock));
        int busy_thread_count = pool->busy_thread_count;
        int pending_task_count = pool->count;
        int current_thread_count = pool->thread_count;
        int started_thread_count = pool->started_n;
        int max_thread_count = pool->max_thread_count;
        int queue_size = pool->queue_size;
        int max_quque_size = pool->max_queue_size;
        pthread_mutex_unlock(&(pool->lock));

        /* 需要增加线程的情况 ：
         *      忙碌的线程大于线程总数 90%
         *      任务队列太大
         **/
        if (started_thread_count <= max_thread_count &&
                busy_thread_count >= started_thread_count * 0.9 ||
                queue_size >= max_quque_size * 0.9)
        {
            for (int i = 0; i < current_thread_count+20; ++i) {
                if (pool->threads[i] == 0 || !is_thread_alive(pool->threads[i])) {
                    pthread_create(&(pool->threads[i]), NULL, threadpool_thread, (void *) pool);
                    return NULL;
                }
                pthread_mutex_lock(&(pool->lock));
                pool->thread_count++;
                pool->started_n++;
                pthread_mutex_unlock(&(pool->lock));
            }
        }

        /**
         * 需要减少线程的情况：
         *      工作的线程很少
         *      等待的任务数量很少
         */
        if (current_thread_count > 0 &&
                    busy_thread_count*2 < current_thread_count ||
                pending_task_count < 10)
        {
            pthread_cond_signal(&(pool->queue_not_empty));
        }
    }
}

int is_thread_alive(pthread_t tid)
{
    int kill_rc = pthread_kill(tid, 0);
    if (kill_rc == ESRCH)
    {
        return 0;
    }
    return 1;
}

static void *threadpool_thread(void *threadpool)
{
    threadpool_t *pool = (threadpool_t *)threadpool;
    threadpool_task_t task;

    for(;;) {
        pthread_mutex_lock(&(pool->busy_thrcount_mutex));
        pool->busy_thread_count ++;
        pthread_mutex_unlock(&(pool->busy_thrcount_mutex));

        /* Lock must be taken to wait on conditional variable */
        pthread_mutex_lock(&(pool->lock));

        /* Wait on condition variable, check for spurious wakeups.
           When returning from pthread_cond_wait(), we own the lock. */
        while((pool->count == 0) && (!pool->shutdown)) {
            pthread_cond_wait(&(pool->queue_not_empty), &(pool->lock));

            if(pool->wait_exit_thread_count > 0 ) {
                pool->wait_exit_thread_count --;

                if(pool->thread_count > 0) {
                    pthread_exit(NULL);
                }
                pthread_mutex_unlock(&(pool->lock));
            }
        }

        if((pool->shutdown == immediate_shutdown) ||
           ((pool->shutdown == graceful_shutdown) &&
            (pool->count == 0))) {
            break;
        }

        /* Grab our task */
        task.function = pool->queue[pool->head].function;
        task.argument = pool->queue[pool->head].argument;
        pool->head += 1;
        pool->head = (pool->head == pool->queue_size) ? 0 : pool->head;
        pool->count -= 1;   // 等待中的任务数量 -1

//        if ((pthread_cond_signal(&(pool->queue_not_full)))!=0) {    // 通知任务队列不满
//            int err = threadpool_lock_failure;
//            break;
//        }

        /* Unlock */
        pthread_mutex_unlock(&(pool->lock));

        /* Exec out task */
        (*(task.function))(task.argument);

        pthread_mutex_lock(&(pool->busy_thrcount_mutex));
        pool->busy_thread_count --;
        pthread_mutex_unlock(&(pool->busy_thrcount_mutex));
    }

    pthread_mutex_lock(&(pool->busy_thrcount_mutex));
    pool->busy_thread_count --;
    pthread_mutex_unlock(&(pool->busy_thrcount_mutex));

    pool->started_n--;

    pthread_mutex_unlock(&(pool->lock));
    pthread_exit(NULL);
    return(NULL);
}
