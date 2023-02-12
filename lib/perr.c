#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "config.h"

static char* restrict progname;

static void show_version()
{
	fprintf(stderr, "%s (%s %s)\n", progname, PACKAGE, PACKAGE_VERSION);
}

void perr(const char *fmt, ...)
{
	va_list args;

	show_version();
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);
	exit(EXIT_FAILURE);
}

void perr_set_progname(char* restrict name)
{
	progname = name;
}

void perr_cannot_allocate_memory(void)
{
	perr("Error: memory allocation failure");
}
