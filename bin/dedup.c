#include "dedup.h"
#include "config.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

static const char* restrict progname = "dedup";

static void usage()
{
	fprintf(stderr, "Usage: %s [-hV] device\n", progname);
}

static void show_version()
{
	fprintf(stderr, "%s (%s %s)\n", progname, PACKAGE, PACKAGE_VERSION);
}

static void parse_options(int argc, char *argv[])
{
	char c;
	while((c = getopt(argc, argv, "hV")) != EOF) {
		switch(c) {
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
	const char* restrict device = argv[optind];

	run(device);
	return 0;
}