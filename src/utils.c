#include <sys/time.h>
#include <stdlib.h>

long    now_ms(void) {
	struct timeval  tv;

	gettimeofday(&tv, NULL);
	return ((long)tv.tv_sec * 1000 + tv.tv_usec / 1000);
}
