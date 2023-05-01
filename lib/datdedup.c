#include "datdedup.h"

#include "nilfs.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <errno.h>
#include <string.h>

int run(const char *device, const struct datdedup_options *options)
{
	const __u64 blocks_to_consider = options->blocks_to_consider;

	printf("Deduplicating with arguments: blocks_to_consider=%lld\n",
	       blocks_to_consider);

	const int result = ioctl(0, NILFS_IOCTL_DEDUP, &blocks_to_consider);

	if (result < 0) {
		printf("Error: %s\n", strerror(errno));
		return result;
	}

	printf("Successfully deduplicated %d blocks\n", result);

	return EXIT_SUCCESS;
}
