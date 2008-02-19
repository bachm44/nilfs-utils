/*
 * xmalloc.c
 *
 * Code borrowed from util-linux-2.12r/mount/xmalloc.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>	/* strdup() */
#include "xmalloc.h"
#include "nls.h"	/* _() */
#include "sundries.h"	/* EX_SYSERR */

void (*at_die)(void) = NULL;

/* Fatal error.  Print message and exit.  */
void
die(int err, const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);

	if (at_die)
		(*at_die)();

	exit(err);
}

static void
die_if_null(void *t) {
	if (t == NULL)
		die(EX_SYSERR, _("not enough memory"));
}

void *
xmalloc (size_t size) {
	void *t;

	if (size == 0)
		return NULL;

	t = malloc(size);
	die_if_null(t);

	return t;
}

void *
xrealloc (void *p, size_t size) {
	void *t;

	t = realloc(p, size);
	die_if_null(t);

	return t;
}

char *
xstrdup (const char *s) {
	char *t;

	if (s == NULL)
		return NULL;

	t = strdup(s);
	die_if_null(t);

	return t;
}
