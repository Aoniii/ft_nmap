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

/**
 * @brief cleanup - Releases every resource held for the whole scan.
 */
static void cleanup(t_work_queue *q, t_net *net, t_config *cfg) {
    pthread_mutex_destroy(&q->lock);
    cleanup_network(net);
    free_target(cfg);
}

/**
 * @brief prepare - Builds the config, targets, network and work queue.
 * Runs the four init steps in order and cleans up whatever was already
 * allocated if one of them fails. Returns 0 on success, -1 on any error.
 */
static int prepare(t_raw_data *raw, char **args, t_config *cfg, t_net *net, t_work_queue *q) {
    if (build_config(raw, cfg) == -1)
        return (-1);

    if (build_target(raw, cfg, args) == -1) {
        free_target(cfg);
        return (-1);
    }

    if (setup_network(net, cfg) == -1) {
        free_target(cfg);
        return (-1);
    }

    if (queue_init(q, net, cfg) == -1) {
        fprintf(stderr, "ft_nmap: error: failed to initialize work queue\n");
        cleanup_network(net);
        free_target(cfg);
        return (-1);
    }

    return (0);
}

/**
 * @brief spoof_note - Warns that spoofing hides the source, so replies never
 * come back and the results are inconclusive. No-op when spoofing is off.
 */
static void spoof_note(t_config *cfg) {
    char    s[INET_ADDRSTRLEN];

    if (!cfg->use_spoof)
        return ;
    inet_ntop(AF_INET, &cfg->spoof_ip, s, sizeof(s));
    printf("\nNote: spoofing source as %s — replies will not return, results will be inconclusive.\n", s);
}

/**
 * @brief run_workers - Runs the scan for the current target.
 * Mono-thread when speedup is 0 (the main thread is the only worker), else it
 * spawns up to speedup workers, never more than there are tasks. Returns 0 on
 * success, -1 if the thread array allocation fails (fatal).
 */
static int run_workers(t_work_queue *q, t_config *cfg) {
    if (cfg->speedup == 0) {
        worker(q);
        return (0);
    }

    // never spawn more workers than there are tasks
    int         nb_threads = (cfg->speedup < q->total_tasks) ? cfg->speedup : q->total_tasks;
    pthread_t   *threads = malloc(sizeof(pthread_t) * nb_threads);

    if (!threads) {
        fprintf(stderr, "ft_nmap: error: failed to alloc threads, aborting scan\n");
        return (-1);
    }

    int created = 0;
    for (int i = 0; i < nb_threads; i++) {
        if (pthread_create(&threads[i], NULL, worker, q) != 0)
            break ;     // stop at the first failure
        created++;
    }

    // join only the threads we created
    for (int i = 0; i < created; i++)
        pthread_join(threads[i], NULL);

    free(threads);
    return (0);
}

/**
 * @brief detect_versions - Grabs the service banner of every open port.
 * Single-threaded (called after all workers joined): no data race on the
 * shared per-port version buffer. One grab per port at most.
 */
static void detect_versions(t_target *target, t_config *cfg) {
    if (!cfg->version)
        return ;

    for (int i = 0; i < cfg->nb_ports; i++) {
        for (int s = 0; s < SCAN_COUNT; s++) {
            if ((cfg->scan_flags & (1 << s)) && target->ports[i].results[s] == STATE_OPEN) {
                grab_version(target->ip, cfg->ports[i], target->ports[i].version, sizeof(target->ports[i].version));
                break ;
            }
        }
    }
}

/**
 * @brief scan_target - Scans one target end to end.
 * Picks the source IP and interface, optionally starts the progress monitor,
 * runs the workers, then does version detection and prints the results.
 * Returns 0 on success (or when the target is simply unreachable and skipped),
 * -1 on a fatal error that must abort the whole scan.
 */
static int scan_target(t_work_queue *q, t_net *net, t_config *cfg, t_target *target) {
    pthread_t   monitor;
    bool        monitor_started = false;
    long        start_time;

    q->target = target;
    q->next_task = 0;
    start_time = now_ms();

    bool use_progress = cfg->progress && isatty(STDOUT_FILENO);
    if (!use_progress)
        printf("\nScanning: %s\n", target->name);

    //  1. IP source for this target
    if (get_source_ip(target->ip, &net->src_ip) != 0) {
        fprintf(stderr, "ft_nmap: warning: cannot reach %s\n", target->name);
        return (0);     // unreachable: skip, not fatal
    }

    //  1b. use the interface that actually routes to this target
    set_device_for_source(net, net->src_ip);

    if (cfg->use_spoof) net->src_ip = cfg->spoof_ip;

    //  launch monitor thread for --progress
    if (use_progress && pthread_create(&monitor, NULL, progress_monitor, q) == 0)
        monitor_started = true;

    //  2. run the scan
    if (run_workers(q, cfg) == -1)
        return (-1);

    //  close monitor
    if (monitor_started) {
        pthread_mutex_lock(&q->lock);
        q->done = true;
        pthread_mutex_unlock(&q->lock);
        pthread_join(monitor, NULL);
    }

    if (q->error) {
        fprintf(stderr, "ft_nmap: error: pcap setup failed, aborting\n");
        return (-1);
    }

    long elapsed = now_ms() - start_time;
    detect_versions(target, cfg);
    show_results(elapsed, target, cfg);
    return (0);
}

/**
 * @brief nmap - Entry point of the scan: prepares the resources, then scans
 * every target in turn, aborting on a fatal error. Returns 0 on success, 1 on
 * error.
 */
int nmap(t_raw_data *raw, char **args) {
    t_config        cfg;
    t_net           net;
    t_work_queue    q;

    if (prepare(raw, args, &cfg, &net, &q) == -1)
        return (1);

    show_config(cfg);
    spoof_note(&cfg);

    for (t_target *target = cfg.targets; target; target = target->next) {
        if (scan_target(&q, &net, &cfg, target) == -1) {
            cleanup(&q, &net, &cfg);
            return (1);
        }
    }

    return (0);
}
