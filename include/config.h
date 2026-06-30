#ifndef CONFIG_H
# define CONFIG_H

typedef struct s_raw_data   t_raw_data;
typedef struct s_config     t_config;

int     build_config(t_raw_data *raw, t_config *cfg);
int     parse_port(t_raw_data *raw, t_config *cfg, char **err);
int     parse_scan(t_raw_data *raw, t_config *cfg, char **err);
int     build_target(t_raw_data *raw, t_config *cfg, char **args);
void    free_target(t_config *cfg);

#endif
