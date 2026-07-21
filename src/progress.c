#include "display.h"
#include "worker.h"
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

/**
 * @brief progress_monitor - Thread displaying a live dashboard of scan progress.
 * Reads next_task under the queue lock, computes the percentage and estimated
 * time remaining, and refreshes a fixed 4-line block in place (~3 fps) using
 * ANSI cursor moves. Exits once the scan is flagged done and all tasks handed out.
 */
void    *progress_monitor(void *arg) {
    t_work_queue    *q = arg;
    long            start = now_ms();
    bool            first = true;

    while (1) {
        pthread_mutex_lock(&q->lock);
        int done  = q->next_task;
        int total = q->total_tasks;
        int over  = q->done;
        pthread_mutex_unlock(&q->lock);

        if (done > total)
            done = total;
        double pct = total ? (100.0 * done / total) : 100.0;

        long   elapsed = now_ms() - start;
        double elapsed_s = elapsed / 1000.0;
        double remaining_s = (done > 0) ? (elapsed * (total - done) / (double)done) / 1000.0 : 0.0;

        // after the first frame, move cursor up 4 lines to overwrite the block
        if (!first)
            printf(C_CUT(3));
        else {
            printf("\n%sScanning %s%s\n", C_BOLD, q->target->name, C_RESET);
            first = false;
        }

        printf("%s   Progress  : %s%.1f%%%s (%d/%d)\n", C_CLEAR, C_GREEN, pct, C_RESET, done, total);
        printf("%s   Elapsed   : %s%.1fs%s\n", C_CLEAR, C_BLUE, elapsed_s, C_RESET);
        printf("%s   Remaining : %s~%.1fs%s\n", C_CLEAR, C_BLUE, remaining_s, C_RESET);
        fflush(stdout);

        if (over && done >= total)
            break;
        usleep(1000000 / 10);   // 10 fps refresh
    }
    return (NULL);
}
