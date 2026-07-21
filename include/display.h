#ifndef DISPLAY_H
# define DISPLAY_H

extern int  g_color;

typedef struct s_config     t_config;
typedef struct s_target     t_target;

# define CLR(c)     (g_color ? (c) : "")

# define C_RESET    CLR("\033[0m")
# define C_GREEN    CLR("\033[32m")
# define C_RED      CLR("\033[31m")
# define C_YELLOW   CLR("\033[33m")
# define C_BLUE     CLR("\033[34m")

# define C_DIM      CLR("\033[2m")
# define C_BOLD     CLR("\033[1m")

# define C_CUT(c)   CLR("\033["#c"A\r")
# define C_CLEAR    CLR("\033[K")

long    now_ms(void);
void    show_config(t_config cfg);
void    show_results(long elapsed, t_target *target, t_config *cfg);
void    *progress_monitor(void *arg);

#endif
