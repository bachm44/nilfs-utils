#ifndef NILFS_DEDUP_H
#define NILFS_DEDUP_H

#include <stdbool.h>
#include <stdint.h>

struct dedup_options {
	uint8_t verbose;
	bool dry_run;
};

int run(const char *restrict device, const struct dedup_options *);

#endif