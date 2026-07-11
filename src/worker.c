#include "worker.h"
#include "network.h"
#include <pcap/pcap.h>
#include <pthread.h>

/**
 * @brief queue_init - Initializes the work queue for the scan.
 * Builds the list of requested scan types from the bitmask (so tasks only
 * cover scans that were asked for), zeroes the counters and error flag, and
 * creates the mutex that guards task handout.
 */
int queue_init(t_work_queue *q, t_net *net, t_config *cfg) {
    q->net      = net;
    q->cfg      = cfg;
    q->error    = 0;

    // build the list of requested scans from the bitmask
    q->nb_scans = 0;
    for (int s = 0; s < SCAN_COUNT; s++)
        if (cfg->scan_flags & (1 << s))
            q->active_scans[q->nb_scans++] = s;

    q->total_tasks = cfg->nb_ports * q->nb_scans;

    if (pthread_mutex_init(&q->lock, NULL) != 0)
        return (-1);
    return (0);
}

/**
 * @brief worker - Thread routine: opens its OWN pcap handle, then pulls tasks.
 * Capturing on a private handle (a local copy of t_net) avoids the concurrency
 * issues of a shared pcap handle. On pcap setup failure it flags q->error so
 * the main thread aborts after join. Tasks are handed out under the lock; the
 * scans run outside it, writing to disjoint result cells (no lock needed).
 */
void    *worker(void *arg) {
    t_work_queue    *q = arg;
    t_net           local_net = *q->net;    // private copy: own handle, shared socket

    // each thread opens ITS OWN pcap handle on the right interface
    if (open_pcap(&local_net, iface_for_target(q->net, q->target->ip)) == -1) {
        pthread_mutex_lock(&q->lock);
        q->error = 1;
        pthread_mutex_unlock(&q->lock);
        return (NULL);
    }

    // and applies ITS OWN capture filter
    if (set_filter(&local_net, q->target->ip) == -1) {
        pthread_mutex_lock(&q->lock);
        q->error = 1;
        pthread_mutex_unlock(&q->lock);
        pcap_close(local_net.handle);
        return (NULL);
    }

    while (1) {
        // --- critical section: grab the next task ---
        pthread_mutex_lock(&q->lock);
        if (q->error) {                  // another thread failed setup: stop
            pthread_mutex_unlock(&q->lock);
            break;
        }
        int task = q->next_task;
        if (task >= q->total_tasks) {
            pthread_mutex_unlock(&q->lock);
            break ;     // no more work
        }
        q->next_task++;
        pthread_mutex_unlock(&q->lock);
        // --- end critical section ---

        // decode the task into (port index, scan type)
        int      port_idx  = task / q->nb_scans;
        int      scan_type = q->active_scans[task % q->nb_scans];
        uint16_t port      = q->cfg->ports[port_idx];

        // run the scan (outside the lock)
        t_state st;
        if (scan_type == SCAN_UDP)
            st = scan_one_udp(&local_net, q->target->ip, port);
        else
            st = scan_one(&local_net, q->target->ip, port, scan_type);

        // store the result in this task's dedicated cell (no lock needed)
        q->target->ports[port_idx].results[scan_type] = st;

        // version detection: only if requested, only on open ports, only once
        if (q->cfg->version && st == STATE_OPEN && q->target->ports[port_idx].version[0] == '\0')
            grab_version(q->target->ip, port, q->target->ports[port_idx].version, sizeof(q->target->ports[port_idx].version));
    }

    pcap_close(local_net.handle);
    return (NULL);
}
