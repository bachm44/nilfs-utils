#include "datdedup.h"

#include "nilfs.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <errno.h>
#include <string.h>

static struct nilfs *nilfs_open_safe(const char *restrict device)
{
	struct nilfs *nilfs =
		nilfs_open(device, NULL, NILFS_OPEN_RDWR | NILFS_OPEN_RAW);
	if (nilfs) {
		fprintf(stderr, "nilfs opened");
	} else {
		fprintf(stderr, "cannot open fs: %s", strerror(errno));
		exit(1);
	}

	return nilfs;
}

int run(const char *device, const struct datdedup_options *options)
{
	const __u64 blocks_to_consider = options->blocks_to_consider;

	printf("Deduplicating with arguments: blocks_to_consider=%lld\n",
	       blocks_to_consider);

	struct nilfs *nilfs = nilfs_open_safe(device);
	const int result = nilfs_dedup(nilfs, blocks_to_consider);
	nilfs_close(nilfs);

	if (result < 0) {
		printf("Error: %s\n", strerror(errno));
		return result;
	}

	printf("Successfully deduplicated %d blocks\n", result);

	return EXIT_SUCCESS;
}
