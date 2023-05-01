#include "config.h"
#include "datdedup.h"

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

static const char *restrict progname = "datdedup";

static void usage()
{
	fprintf(stderr, "Usage: %s [-hV] [-v] device\n", progname);
}

static void show_version()
{
	fprintf(stderr, "%s (%s %s)\n", progname, PACKAGE, PACKAGE_VERSION);
}

static void parse_options(int argc, char *argv[])
{
	char c;
	while ((c = getopt(argc, argv, "hV")) != EOF) {
		switch (c) {
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
		case 'V':
			show_version();
			exit(EXIT_SUCCESS);
		default:
			usage();
			exit(EXIT_FAILURE);
		}
	}
}

int main(int argc, char *argv[])
{
	parse_options(argc, argv);
	const char *restrict device = argv[optind];

	uint64_t blocks_to_consider = -1;
	if (argc > ++optind)
		blocks_to_consider = atoi(argv[optind]);

	const struct datdedup_options options = { .blocks_to_consider =
							  blocks_to_consider };

	if (!device || device[0] == '\0') {
		fprintf(stderr, "Device should not be empty\n");
		usage();
		exit(EXIT_FAILURE);
	}

	return run(device, &options);
}