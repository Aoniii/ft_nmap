#include "ft_nmap.h"
#include "parser.h"
#include "display.h"
#include <stddef.h>
#include <unistd.h>

int g_color = 0;

int main(int argc, char **argv) {
    t_parser_ctx    ctx;
    ctx.err = PARSER_SUCCESS;

    t_parser_info   info = {
        .program        = argv[0],
        #if POSITIONAL_TARGET
        .usage          = "[OPTIONS] <ip|hostname>... or --file FILE",
        #else
        .usage          = "[OPTIONS] --ip <ip|hostname> or --file FILE",
        #endif
        .description    = "\nft_nmap - a multithreaded port scanner.\n"
                          "Scans the given targets using raw sockets and pcap,\n"
                          "reporting the state of each port per scan type.\n",
        .footer         = "\nMade by snourry & stales - https://github.com/Aoniii/ft_nmap\n"
    };

    t_raw_data  data = {
        .ip = NULL,
        .file = NULL,
        .port = NULL,
        .scan = NULL,
        .speedup = 0,
        .dns = false,
        .open = false,
        .progress = false,
    };

    t_option    options[] = {
        CATEGORY("Target Specification\n"),
        #if !POSITIONAL_TARGET
        {
            .short_opt  = 0,
            .long_opt   = "ip",
            .flags      = OPT_LONG | TYPE_STRING,
            .value      = &data.ip,
            .help       = "Single IP address or hostname to scan"
        },
        #endif
        {
            .short_opt  = 'f',
            .long_opt   = "file",
            .flags      = OPT_SHORT | OPT_LONG | TYPE_STRING,
            .value      = &data.file,
            .help       = "Read targets from a file"
        },
        CATEGORY("Scan Options\n"),
        {
            .short_opt  = 'p',
            .long_opt   = "ports",
            .flags      = OPT_SHORT | OPT_LONG | TYPE_STRING,
            .value      = &data.port,
            .help       = "Ports to scan: 1-1024, 80,443 or 1,5-15 (default: 1-1024, max: 1024)"
        },
        {
            .short_opt  = 's',
            .long_opt   = "scan",
            .flags      = OPT_SHORT | OPT_LONG | TYPE_STRING,
            .value      = &data.scan,
            .help       = "Scan types: SYN/NULL/FIN/XMAS/ACK/UDP, '/'-separated (default: all)"
        },
        {
            .short_opt  = 0,
            .long_opt   = "version-detection",
            .flags      = OPT_LONG | TYPE_BOOLEAN,
            .value      = &data.version,
            .help       = "Probe open ports to identify service and version"
        },
        CATEGORY("Performance\n"),
        {
            .short_opt  = 0,
            .long_opt   = "speedup",
            .flags      = OPT_LONG | TYPE_INT,
            .value      = &data.speedup,
            .help       = "Number of parallel threads (0 = single-threaded, max: 250)"
        },
        CATEGORY("Resolution\n"),
        {
            .short_opt  = 0,
            .long_opt   = "reverse-dns",
            .flags      = OPT_LONG | TYPE_BOOLEAN,
            .value      = &data.dns,
            .help       = "Resolve IP addresses back to hostnames (slower)"
        },
        CATEGORY("Display\n"),
        {
            .short_opt  = 0,
            .long_opt   = "open",
            .flags      = OPT_LONG | TYPE_BOOLEAN,
            .value      = &data.open,
            .help       = "Show only open ports, hide closed and filtered"
        },
        {
            .short_opt  = 0,
            .long_opt   = "progress",
            .flags      = OPT_LONG | TYPE_BOOLEAN,
            .value      = &data.progress,
            .help       = "Show a live progress dashboard during the scan"
        },
        CATEGORY("Misc\n"),
        {
			.short_opt  = 0,
			.long_opt   = "help",
			.flags      = OPT_LONG | OPT_CALLBACK_EXIT | TYPE_CALLBACK,
			.value      = (void *)&(t_callback_info){
				.fn = callback_help,
				.data = (void *)&(t_help_data){
					.info = info,
					.options = options
				}
			},
			.help       = "Print this help screen and exit"
		},
        {0}
    };

    char **args = parser(argc, argv, options, MODE_PERMISSIVE, &ctx);
    if (ctx.err != PARSER_SUCCESS) {
		error(info.program, &ctx);
		cleaner(args);
		return (ctx.err == CALLBACK_EXIT ? 0 : 1);
	}

    g_color = isatty(STDOUT_FILENO);
    int ret = nmap(&data, args);

    cleaner(args);
    return (ret);
}
