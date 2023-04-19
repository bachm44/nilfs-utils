#include "dedup.h"
#include "config.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

static const char *restrict progname = "dedup";

static void usage()
{
	fprintf(stderr, "Usage: %s [-hV] [-v] device\n", progname);
}

static void show_version()
{
	fprintf(stderr, "%s (%s %s)\n", progname, PACKAGE, PACKAGE_VERSION);
}

static void parse_options(int argc, char *argv[], struct dedup_options *options)
{
	char c;
	while ((c = getopt(argc, argv, "hV:v")) != EOF) {
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
		default:
			usage();
			exit(EXIT_FAILURE);
		}
	}
}

int main(int argc, char *argv[])
{
	struct dedup_options options = { .verbose = 0 };
	parse_options(argc, argv, &options);
	const char *restrict device = argv[optind];

	if (!device || device[0] == '\0') {
		fprintf(stderr, "Device should not be empty\n");
		usage();
		exit(EXIT_FAILURE);
	}

	return run(device, &options);
}