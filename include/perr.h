#ifndef PERR_H
#define PERR_H

void perr(const char *fmt, ...);
void perr_set_progname(char* restrict name);
void perr_cannot_allocate_memory(void);

#endif
