#include "ft_nmap.h"
#include "parser.h"

int main(int argc, char **argv) {
    t_parser_ctx    ctx;
    ctx.err = PARSER_SUCCESS;

    t_parser_info   info = {
        .program        = argv[0],
        .usage          = "",
        .description    = "",
        .footer         = ""
    };

    t_raw_data  data = {
        .file = NULL,
        .port = NULL,
        .scan = NULL,
        .speedup = 0,
    };

    t_option    options[] = {
        {
            .short_opt  = 'f',
            .long_opt   = "file",
            .flags      = OPT_SHORT | OPT_LONG | TYPE_STRING,
            .value      = &data.file,
            .help       = "file name containing IP addresses to scan"
        },
        {
            .short_opt  = 'p',
            .long_opt   = "port",
            .flags      = OPT_SHORT | OPT_LONG | TYPE_STRING,
            .value      = &data.port,
            .help       = "ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)"
        },
        {
            .short_opt  = 0,
            .long_opt   = "scan",
            .flags      = OPT_LONG | TYPE_STRING,
            .value      = &data.scan,
            .help       = "SYN/NULL/FIN/XMAS/ACK/UDP"
        },
        {
            .short_opt  = 0,
            .long_opt   = "speedup",
            .flags      = OPT_LONG | TYPE_INT,
            .value      = &data.speedup,
            .help       = "[250 max] number of parallel threads to use"
        },
        {
			.short_opt	= 0,
			.long_opt	= "help",
			.flags		= OPT_LONG | OPT_CALLBACK_EXIT | TYPE_CALLBACK,
			.value		= (void *)&(t_callback_info){
				.fn = callback_help,
				.data = (void *)&(t_help_data){
					.info = info,
					.options = options
				}
			},
			.help		= "print this help screen"
		},
        {0}
    };

    char **args = parser(argc, argv, options, MODE_PERMISSIVE, &ctx);
    if (ctx.err != PARSER_SUCCESS) {
		error(info.program, &ctx);
		cleaner(args);
		return (ctx.err == CALLBACK_EXIT ? 0 : 1);
	}

    // Test
    t_config    cfg;

    if (build_config(&data, &cfg) == -1)
        return (-1);

    printf("Ports: ");
    for (int i = 0; i < cfg.nb_ports; i++) {
        printf("%i ", cfg.ports[i]);
    }
    printf("\n");

    static const uint8_t  type_flag[] = {F_SYN, F_NULL, F_ACK, F_FIN, F_XMAS, F_UDP};
    static const char    *str_flag[]  = {"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP"};

    printf("Scans: ");
    for (int i = 0; i < 6; i++) {
        if (cfg.scan_flags & type_flag[i])
            printf("%s ", str_flag[i]);
    }
    printf("\n");

    cleaner(args);
    return (0);
}
