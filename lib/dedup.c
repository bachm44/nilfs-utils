#include "dedup.h"
#include "nilfs.h"
#include "perr.h"
#include "util.h"
#include "vector.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syslog.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>


static void default_logger(int priority, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);
}

static void (*nilfs_dedup_logger)(int priority, const char *fmt, ...) = default_logger;


/*
taken from sbin/mkfs.c:825-851
*/

typedef uint64_t  blocknr_t;
static void **disk_buffer;
static unsigned long disk_buffer_size;

#define NILFS_DEF_BLOCKSIZE_BITS	12   /* default blocksize = 2^12
						bytes */
#define NILFS_DEF_BLOCKSIZE	        (1 << NILFS_DEF_BLOCKSIZE_BITS)
static unsigned long blocksize = NILFS_DEF_BLOCKSIZE;
static void init_disk_buffer(long max_blocks);
static void destroy_disk_buffer(void);
static void *map_disk_buffer(blocknr_t blocknr, int clear_flag);

static void destroy_disk_buffer(void)
{
	if (disk_buffer) {
		void **pb = disk_buffer, **ep = disk_buffer + disk_buffer_size;

		while (pb < ep) {
			if (*pb)
				free(*pb);
			pb++;
		}
		free(disk_buffer);
		disk_buffer = NULL;
	}
}

static void init_disk_buffer(long max_blocks)
{
	disk_buffer = calloc(max_blocks, sizeof(void *));
	if (!disk_buffer)
		perr_cannot_allocate_memory();

	memset(disk_buffer, 0, max_blocks * sizeof(void *));
	disk_buffer_size = max_blocks;

	atexit(destroy_disk_buffer);
}

static void *map_disk_buffer(blocknr_t blocknr, int clear_flag)
{
	if (blocknr >= disk_buffer_size)
		perr("Internal error: illegal disk buffer access (blocknr=%llu)",
		     blocknr);

	if (!disk_buffer[blocknr]) {
		if (posix_memalign(&disk_buffer[blocknr], blocksize,
				   blocksize) != 0)
			perr_cannot_allocate_memory();
		if (clear_flag)
			memset(disk_buffer[blocknr], 0, blocksize);
	}
	return disk_buffer[blocknr];
}

static struct nilfs* nilfs_open_safe()
{
	struct nilfs *nilfs =
		nilfs_open("/dev/loop0", NULL, NILFS_OPEN_RDWR | NILFS_OPEN_RAW);
	if (nilfs) {
		nilfs_dedup_logger(LOG_INFO, "nilfs opened");
	} else {
		nilfs_dedup_logger(LOG_ERR, "error: cannot open fs: %s", strerror(errno));
		exit(1);
	}

	return nilfs;
}

static void nilfs_segment_free(struct nilfs_segment *segment)
{
	free(segment->addr);
	free(segment);
}

static void nilfs_suinfo_print(const struct nilfs_suinfo* si) 
{
	printf("nilfs_suinfo {\n");
	printf("	nblocks = %d\n", si->sui_nblocks);
	printf("	lastmod = %lld\n", si->sui_lastmod);
	printf("}\n\n");
}

static void nilfs_segment_print(const struct nilfs_segment* segment)
{
	printf("nilfs_segment {\n");
	printf("	addr = %p,\n", segment->addr);
	printf("	segsize = %ld,\n", segment->segsize);
	printf("	seqnum = %ld,\n", segment->seqnum);
	printf("	blocknr = %ld,\n", segment->blocknr);
	printf("	nblocks = %d,\n", segment->nblocks);
	printf("	blocks_per_segment = %d,\n",
	       segment->blocks_per_segment);
	printf("	blkbits = %d,\n", segment->blkbits);
	printf("	seed = %d,\n", segment->seed);
	printf("	mmaped = %d,\n", segment->mmapped);
	printf("	adjusted = %d,\n", segment->adjusted);
	printf("}\n\n");
}

static void nilfs_layout_print(const struct nilfs_layout* layout)
{
	printf("nilfs_layout {\n");
	printf("	rev_level = %d\n", layout->rev_level);
	printf("	minor_rev_level = %d\n", layout->minor_rev_level);
	printf("	flags = %d\n", layout->flags);
	printf("	blocksize_bits = %d\n", layout->blocksize_bits);
	printf("	blocksize = %d\n", layout->blocksize);
	printf("	devsize = %ld\n", layout->devsize);
	printf("	crc_seed = %d\n", layout->crc_seed);
	printf("	pad = %d\n", layout->pad);
	printf("	nsegments = %ld\n", layout->nsegments);
	printf("	blocks_per_segment = %d\n", layout->blocks_per_segment);
	printf("	reserved_segments_ratio = %d\n", layout->reserved_segments_ratio);
	printf("	first_segment_blkoff = %ld\n", layout->first_segment_blkoff);
	printf("	feature_compat = %ld\n", layout->feature_compat);
	printf("	feature_compat_ro = %ld\n", layout->feature_compat_ro);
	printf("	feature_incompat = %ld\n", layout->feature_incompat);
	printf("}\n\n");
}

static void nilfs_sustat_print(const struct nilfs_sustat* sustat)
{
	printf("nilfs_sustat {\n");
	printf("	ss_nsegs = %lld\n", sustat->ss_nsegs);
	printf("	ss_ncleansegs = %lld\n", sustat->ss_ncleansegs);
	printf("	ss_ndirtysegs = %lld\n", sustat->ss_ndirtysegs);
	printf("	ss_ctime = %lld\n", sustat->ss_ctime);
	printf("	ss_nongc_ctime = %lld\n", sustat->ss_nongc_ctime);
	printf("	ss_prot_seq = %lld\n", sustat->ss_prot_seq);
	printf("}\n\n");
}

static void fetch_disk_buffer()
{
	const char* restrict device = "nilfs.bin";
	int fd = open(device, O_RDWR);
	lseek(fd, 0, SEEK_SET);
	for (size_t i = 0; i < 512; ++i) {
		if(read(fd, map_disk_buffer(i, 0), blocksize) < 0) {
			printf("error: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
}

static void print_block_content(int blocknr)
{
	const void* restrict content = map_disk_buffer(blocknr, 0);
	printf("======================== BLOCK NUMBER %d ========================\n", blocknr);
	fwrite(content, blocksize, 1, stdout);
	printf("\n======================== END BLOCK NUMBER %d ========================\n", blocknr);
}

void run()
{
	init_disk_buffer(1000000);
	fetch_disk_buffer();

	struct nilfs* nilfs = nilfs_open_safe();
	struct nilfs_layout layout;
	nilfs_get_layout(nilfs, &layout, sizeof(struct nilfs_layout));
	nilfs_layout_print(&layout);

	struct nilfs_sustat sustat;
	nilfs_get_sustat(nilfs, &sustat);
	nilfs_sustat_print(&sustat);

	printf("block_size = %ld\n", nilfs_get_block_size(nilfs));
	printf("blocks_per_segment = %d\n", nilfs_get_blocks_per_segment(nilfs));
	printf("reserved_segments_ratio = %d\n", nilfs_get_reserved_segments_ratio(nilfs));

	 struct nilfs_vector *bdescv =
		nilfs_vector_create(sizeof(struct nilfs_bdesc));
	struct nilfs_vector *vdescv = nilfs_vector_create(sizeof(struct nilfs_vdesc));

	if (!bdescv || !vdescv) {
		nilfs_dedup_logger(LOG_ERR, "error: cannot allocate vector: %s", strerror(errno));
		exit(1);
	}

	const int nsegments = nilfs_get_nsegments(nilfs);

	struct nilfs_suinfo si;

	for (size_t segment_number = 0; segment_number < nsegments; ++segment_number)
	{
		struct nilfs_segment *segment = malloc(sizeof(struct nilfs_segment));

		if(unlikely(nilfs_get_segment(nilfs, segment_number, segment) < 0)) {
			nilfs_dedup_logger(LOG_ERR, "error: cannot fetch segment");
			exit(1);
		}

		if(unlikely(nilfs_get_suinfo(nilfs, segment_number, &si, 1) < 0)) {
			nilfs_dedup_logger(LOG_ERR, "error: cannot fetch suinfo");
			exit(1);
		}

		if (si.sui_nblocks == 0) {
			continue;
		}

		// nilfs_acc_blocks_segment(segment, si.sui_nblocks, vdescv, bdescv);

		printf("SEGMENT NUMBER: %zu\n",segment_number);
		nilfs_suinfo_print(&si);
		nilfs_segment_print(segment);

		const int block_start = segment->blocknr;
		const int block_end = block_start + si.sui_nblocks;

		for (int blocknr = block_start; blocknr < block_end; ++blocknr) {
			print_block_content(blocknr);
		}
			/*
		Modify function 'fill_in_checksums' from sbin/mkfs.c:1631
		to get checksums from suinfo for each data block.

		Then implement content extraction from
		those blocks.
		*/

		nilfs_segment_free(segment);
	}

	// if (unlikely(nilfs_get_bdesc(nilfs, bdescv) < 0)) {
	// 	nilfs_dedup_logger(LOG_ERR, "error: cannot read disk block descriptors: %s", strerror(errno));
	// 	exit(1);
	// }

	nilfs_close(nilfs);
	nilfs_vector_destroy(bdescv);
	nilfs_vector_destroy(vdescv);
}