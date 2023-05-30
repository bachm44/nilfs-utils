#include "dedup.h"
#include "config.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

static const char *restrict progname = "dedup";
#define DEDUP_USAGE                                                                          \
	"Usage: %s [-hVn] [-v] device\n"                                                     \
	"dedup -- A program for block-level deduplication for the Nilfs2 filesystem\n"       \
	"\n"                                                                                 \
	" -h		Show help and exit\n"                                                          \
	" -V		Print program version and exit\n"                                              \
	" -v		Verbose output (LOG_INFO and down)\n"                                          \
	" -vv		Verbose output (LOG_DEBUG and down)\n"                                        \
	" -n		Dry run - gather all blocks from segments but without submit to dedup ioctl\n" \
	"\n"

static void usage()
{
	fprintf(stderr, DEDUP_USAGE, progname);
}

static void show_version()
{
	fprintf(stderr, "%s (%s %s)\n", progname, PACKAGE, PACKAGE_VERSION);
}

static void parse_options(int argc, char *argv[], struct dedup_options *options)
{
	char c;
	while ((c = getopt(argc, argv, "hVnv")) != EOF) {
		switch (c) {
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
		case 'V':
			show_version();
			exit(EXIT_SUCCESS);
		case 'v':
			options->verbose++;
			continue;
		case 'n':
			options->dry_run = true;
			continue;
		default:
			usage();
			exit(EXIT_FAILURE);
		}
	}
}

int main(int argc, char *argv[])
{
	struct dedup_options options = { .verbose = 0, .dry_run = false };
	parse_options(argc, argv, &options);
	const char *restrict device = argv[optind];

	if (!device || device[0] == '\0') {
		fprintf(stderr, "Device should not be empty\n");
		usage();
		exit(EXIT_FAILURE);
	}

	return run(device, &options);
}