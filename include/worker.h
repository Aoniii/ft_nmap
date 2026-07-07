#ifndef WORKER_H
# define WORKER_H

# include "ft_nmap.h"
# include <bits/pthreadtypes.h>

typedef struct s_net    t_net;

/**
 * @brief Work queue - distributes (port × requested-scan) tasks across threads.
 * active_scans holds only the scan types actually requested, so no task is
 * ever wasted on a disabled scan. Each thread locks the queue, grabs the next
 * task index, unlocks, then scans outside the lock. Results go into disjoint
 * ports[] cells, so no mutex is needed on the results.
 */
typedef struct      s_work_queue {
    t_net           *net;                       // shared network resources
    t_target        *target;                    // current target being scanned
    t_config        *cfg;                       // config (ports, scan_flags)
    pthread_mutex_t lock;                       // protects next_task
    int             active_scans[SCAN_COUNT];   // request scan types, in order
    int             nb_scans;                   // how many are requested
    int             next_task;                  // next task index to hand out
    int             total_tasks;                // nb_ports * nb_scans
    int             error;                      // set by any worker that fails pcap setup
}                   t_work_queue;

int     queue_init(t_work_queue *q, t_net *net, t_config *cfg);
void    *worker(void *arg);

#endif
