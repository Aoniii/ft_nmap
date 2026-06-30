#ifndef DISPLAY_H
# define DISPLAY_H

typedef struct s_config     t_config;

long    now_ms(void);
void    show_target_ip(t_config cfg);
void    show_scan(t_config cfg);

#endif
