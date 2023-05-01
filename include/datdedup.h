#ifndef NILFS_DATDEDUP_H
#define NILFS_DATDEDUP_H

#include <stdint.h>
struct datdedup_options {
	uint64_t blocks_to_consider;
};

int run(const char *device, const struct datdedup_options *);

#endif