#ifndef NILFS_DEDUP_H
#define NILFS_DEDUP_H

#include <stdint.h>
struct dedup_options {
	uint8_t verbose;
};

int run(const char *restrict device, const struct dedup_options *);

#endif