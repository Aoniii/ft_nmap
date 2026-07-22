#include "network.h"
#include "config.h"
#include "display.h"
#include "worker.h"
#include <arpa/inet.h>
#include <bits/pthreadtypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void cleanup(t_work_queue *q, t_net *net, t_config *cfg) {
    pthread_mutex_destroy(&q->lock);
    cleanup_network(net);
    free_target(cfg);
}

int nmap(t_raw_data *raw, char **args) {
    t_target        *target;
    t_config        cfg;
    t_net           net;
    t_work_queue    q;
    long            start_time;

    if (build_config(raw, &cfg) == -1)
        return (-1);

    if (build_target(raw, &cfg, args) == -1) {
        free_target(&cfg);
        return (-1);
    }

    if (setup_network(&net) == -1) {
        free_target(&cfg);
        return (-1);
    }

    if (queue_init(&q, &net, &cfg) == -1) {
        fprintf(stderr, "ft_nmap: error: failed to initialize work queue\n");
        cleanup_network(&net);
        free_target(&cfg);
        return (-1);
    }

    show_config(cfg);
    target = cfg.targets;

    while (target) {
        q.target = target;
        q.next_task = 0;
        start_time = now_ms();

        bool use_progress = cfg.progress && isatty(STDOUT_FILENO);
        if (!use_progress)
            printf("\nScanning: %s\n", target->name);

        //  1. IP source for this target
        if (get_source_ip(target->ip, &net.src_ip) != 0) {
            fprintf(stderr, "ft_nmap: warning: cannot reach %s\n", target->name);
            target = target->next;
            continue ;
        }

        // launch monitor thread for --progress
        pthread_t   monitor;
        bool        monitor_started = false;
        if (use_progress) {
            if (pthread_create(&monitor, NULL, progress_monitor, &q) == 0)
                monitor_started = true;
        }

        //  2. run the scan: mono-thread if speedup is 0, else N worker threads
        if (cfg.speedup == 0) {
            // mono-thread: the main thread is the only worker
            worker(&q);
        } else {
            // multi-thread: create N workers and wait for them
            pthread_t *threads = malloc(sizeof(pthread_t) * cfg.speedup);
            if (!threads) {
                fprintf(stderr, "ft_nmap: error: failed to alloc threads, aborting scan\n");
                cleanup(&q, &net, &cfg);
                return (-1);
            }

            int created = 0;
            for (int i = 0; i < cfg.speedup; i++) {
                if (pthread_create(&threads[i], NULL, worker, &q) != 0)
                    break ;     // stop at the first failure
                created++;
            }

            // join only the threads we created
            for (int i = 0; i < created; i++)
                pthread_join(threads[i], NULL);

            free(threads);
        }

        // close monitor
        if (monitor_started) {
            pthread_mutex_lock(&q.lock);
            q.done = true;
            pthread_mutex_unlock(&q.lock);
            pthread_join(monitor, NULL);
        }

        if (q.error) {
            fprintf(stderr, "ft_nmap: error: pcap setup failed, aborting\n");
            cleanup(&q, &net, &cfg);
            return (-1);
        }

        show_results(now_ms() - start_time, target, &cfg);
        target = target->next;
    }

    cleanup(&q, &net, &cfg);
    return (0);
}
