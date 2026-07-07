#include "worker.h"
#include "network.h"
#include <pthread.h>

int queue_init(t_work_queue *q, t_net *net, t_config *cfg) {
    q->net    = net;
    q->cfg    = cfg;

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

void    *worker(void *arg) {
    t_work_queue    *q = arg;

    while (1) {
        // --- critical section: grab the next task ---
        pthread_mutex_lock(&q->lock);
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
            st = scan_one_udp(q->net, q->target->ip, port);
        else
            st = scan_one(q->net, q->target->ip, port, scan_type);

        // store the result in this task's dedicated cell (no lock needed)
        q->target->ports[port_idx].results[scan_type] = st;
    }
    return (NULL);
}
