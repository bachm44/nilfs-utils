#include "dedup.h"
#include "compat.h"
#include "nilfs.h"
#include "nilfs2_api.h"
#include "nilfs2_ondisk.h"
#include "perr.h"
#include "util.h"
#include "vector.h"
#include "crc32.h"
#include "segment.h"

#include <ftw.h>
#include <errno.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syslog.h>

// TODO move this var to configure.ac
// Temporary walkaround for large file functions
#define __USE_LARGEFILE64
#include <unistd.h>

#define __USE_LARGEFILE64
#include <fcntl.h>

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

#undef NDEBUG

#define BUFFER_SIZE 1000000
typedef __u64 sector_t;

#define nilfs_crc32(seed, data, length) crc32_le(seed, data, length)

static const struct dedup_options *dedup_options;

// ===============================================================================
// logging
// ===============================================================================

static void default_logger(int priority, const char *fmt, ...)
{
	va_list args;

	switch (priority) {
	case LOG_DEBUG:
		if (dedup_options->verbose < 2)
			return;
		fprintf(stderr, "DEBUG |");
		break;

	case LOG_INFO:
		if (dedup_options->verbose < 1)
			return;
		fprintf(stderr, "INFO  |");
		break;

	case LOG_NOTICE:
		fprintf(stderr, "NOTICE|");
		break;

	case LOG_WARNING:
		fprintf(stderr, "WARN  |");
		break;

	case LOG_ERR:
		fprintf(stderr, "ERROR |");
		break;

	case LOG_CRIT:
		fprintf(stderr, "CRIT  |");
		break;

	case LOG_ALERT:
		fprintf(stderr, "ALERT |");
		break;

	case LOG_EMERG:
		fprintf(stderr, "EMERG |");
		break;

	default:
		fprintf(stderr, "UNKNWN|");
	}

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);
}

static void (*logger)(int priority, const char *fmt, ...) = default_logger;

// ===============================================================================
// end of logging
// ===============================================================================

// ===============================================================================
// disk_buffer
// ===============================================================================

/*
taken from sbin/mkfs.c:825-851
*/

typedef uint64_t blocknr_t;
static void **disk_buffer;
static const unsigned long disk_buffer_size = 1024;
static unsigned long disk_buffer_block_sector = 0;
static const char *device;

#define NILFS_DEF_BLOCKSIZE_BITS \
	12 /* default blocksize = 2^12
						bytes */
#define NILFS_DEF_BLOCKSIZE (1 << NILFS_DEF_BLOCKSIZE_BITS)

static const unsigned long blocksize = NILFS_DEF_BLOCKSIZE;
static void init_disk_buffer(void);
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

static void init_disk_buffer(void)
{
	logger(LOG_DEBUG, "%s:%d:%s", __FILE__, __LINE__, __FUNCTION__);
	disk_buffer = calloc(disk_buffer_size, sizeof(void *));
	if (!disk_buffer)
		perr_cannot_allocate_memory();

	memset(disk_buffer, 0, disk_buffer_size * sizeof(void *));
	atexit(destroy_disk_buffer);
}

static void *map_disk_buffer(blocknr_t blocknr, int clear_flag)
{
	if (!disk_buffer[blocknr]) {
		if (posix_memalign(&disk_buffer[blocknr], blocksize,
				   blocksize) != 0)
			perr_cannot_allocate_memory();
		if (clear_flag)
			memset(disk_buffer[blocknr], 0, blocksize);
	}
	return disk_buffer[blocknr];
}

static void fetch_disk_buffer(off_t sector_start_blocknr)
{
	logger(LOG_DEBUG, "initializing buffer with start blocknr %d",
	       sector_start_blocknr);
	const int fd = open64(device, O_RDWR);
	if (unlikely(fd < 0)) {
		logger(LOG_ERR, "cannot fetch disk buffer: %s",
		       strerror(errno));
		exit(EXIT_FAILURE);
	}

	const off64_t disk_sector = sector_start_blocknr * blocksize;

	for (size_t i = 0; i < disk_buffer_size; ++i) {
		if (pread64(fd, map_disk_buffer(i, 0), blocksize, disk_sector) <
		    0) {
			logger(LOG_ERR,
			       "cannot map disk buffer for fd = %d, blocksize = %lld: %s",
			       fd, blocksize, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if ((close(fd)) < 0) {
		logger(LOG_ERR, "failed to close file: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
}

static void *fetch_disk_block(blocknr_t blocknr)
{
	off_t sector_next_start_blocknr =
		(disk_buffer_block_sector + 1) * disk_buffer_size;

	while ((off_t)blocknr >= (sector_next_start_blocknr)) {
		destroy_disk_buffer();
		init_disk_buffer();
		fetch_disk_buffer(sector_next_start_blocknr);
		++disk_buffer_block_sector;
		sector_next_start_blocknr =
			(disk_buffer_block_sector + 1) * disk_buffer_size;
	}

	const size_t index = blocknr % disk_buffer_size;

	if (!disk_buffer || !disk_buffer[index]) {
		logger(LOG_ERR,
		       "failed to fetch disk buffer for blocknr = %ld, sector_start_blocknr = %ld",
		       blocknr, sector_next_start_blocknr - disk_buffer_size);
		exit(EXIT_FAILURE);
	}

	return disk_buffer[index];
}

// ===============================================================================
// end of disk_buffer
// ===============================================================================

// ===============================================================================
// nilfs utils
// ===============================================================================

static struct nilfs *nilfs_open_safe(const char *restrict device)
{
	logger(LOG_DEBUG, "%s:%d:%s", __FILE__, __LINE__, __FUNCTION__);

	struct nilfs *nilfs =
		nilfs_open(device, NULL, NILFS_OPEN_RDWR | NILFS_OPEN_RAW);
	if (nilfs) {
		logger(LOG_INFO, "nilfs opened");
	} else {
		logger(LOG_ERR, "cannot open fs: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	return nilfs;
}

// ===============================================================================
// end of nilfs utils
// ===============================================================================

// ===============================================================================
// debug print functions
// ===============================================================================

static void print_nilfs_suinfo(const struct nilfs_suinfo *si)
{
	logger(LOG_DEBUG, "%s:%d:%s", __FILE__, __LINE__, __FUNCTION__);

	logger(LOG_DEBUG, "nilfs_suinfo {");
	logger(LOG_DEBUG, "	nblocks = %d", si->sui_nblocks);
	logger(LOG_DEBUG, "	lastmod = %lld", si->sui_lastmod);
	logger(LOG_DEBUG, "}");
}

static void print_nilfs_segment(const struct nilfs_segment *segment)
{
	logger(LOG_DEBUG, "%s:%d:%s", __FILE__, __LINE__, __FUNCTION__);

	logger(LOG_DEBUG, "nilfs_segment {");
	logger(LOG_DEBUG, "	addr = %p,", segment->addr);
	logger(LOG_DEBUG, "	segsize = %ld,", segment->segsize);
	logger(LOG_DEBUG, "	seqnum = %ld,", segment->seqnum);
	logger(LOG_DEBUG, "	blocknr = %ld,", segment->blocknr);
	logger(LOG_DEBUG, "	nblocks = %d,", segment->nblocks);
	logger(LOG_DEBUG, "	blocks_per_segment = %d,",
	       segment->blocks_per_segment);
	logger(LOG_DEBUG, "	blkbits = %d,", segment->blkbits);
	logger(LOG_DEBUG, "	seed = %d,", segment->seed);
	logger(LOG_DEBUG, "	mmaped = %d,", segment->mmapped);
	logger(LOG_DEBUG, "	adjusted = %d,", segment->adjusted);
	logger(LOG_DEBUG, "}");
}

static void print_nilfs_layout(const struct nilfs *nilfs)
{
	logger(LOG_DEBUG, "%s:%d:%s", __FILE__, __LINE__, __FUNCTION__);

	struct nilfs_layout layout;
	nilfs_get_layout(nilfs, &layout, sizeof(struct nilfs_layout));

	logger(LOG_DEBUG, "nilfs_layout {");
	logger(LOG_DEBUG, "	rev_level = %d", layout.rev_level);
	logger(LOG_DEBUG, "	minor_rev_level = %d", layout.minor_rev_level);
	logger(LOG_DEBUG, "	flags = %d", layout.flags);
	logger(LOG_DEBUG, "	blocksize_bits = %d", layout.blocksize_bits);
	logger(LOG_DEBUG, "	blocksize = %d", layout.blocksize);
	logger(LOG_DEBUG, "	devsize = %ld", layout.devsize);
	logger(LOG_DEBUG, "	crc_seed = %d", layout.crc_seed);
	logger(LOG_DEBUG, "	pad = %d", layout.pad);
	logger(LOG_DEBUG, "	nsegments = %ld", layout.nsegments);
	logger(LOG_DEBUG, "	blocks_per_segment = %d",
	       layout.blocks_per_segment);
	logger(LOG_DEBUG, "	reserved_segments_ratio = %d",
	       layout.reserved_segments_ratio);
	logger(LOG_DEBUG, "	first_segment_blkoff = %ld",
	       layout.first_segment_blkoff);
	logger(LOG_DEBUG, "	feature_compat = %ld", layout.feature_compat);
	logger(LOG_DEBUG, "	feature_compat_ro = %ld",
	       layout.feature_compat_ro);
	logger(LOG_DEBUG, "	feature_incompat = %ld",
	       layout.feature_incompat);
	logger(LOG_DEBUG, "}");
}

static void print_nilfs_sustat(const struct nilfs *nilfs)
{
	logger(LOG_DEBUG, "%s:%d:%s", __FILE__, __LINE__, __FUNCTION__);

	struct nilfs_sustat sustat;

	nilfs_get_sustat(nilfs, &sustat);

	logger(LOG_DEBUG, "nilfs_sustat {");
	logger(LOG_DEBUG, "	ss_nsegs = %lld", sustat.ss_nsegs);
	logger(LOG_DEBUG, "	ss_ncleansegs = %lld", sustat.ss_ncleansegs);
	logger(LOG_DEBUG, "	ss_ndirtysegs = %lld", sustat.ss_ndirtysegs);
	logger(LOG_DEBUG, "	ss_ctime = %lld", sustat.ss_ctime);
	logger(LOG_DEBUG, "	ss_nongc_ctime = %lld", sustat.ss_nongc_ctime);
	logger(LOG_DEBUG, "	ss_prot_seq = %lld", sustat.ss_prot_seq);
	logger(LOG_DEBUG, "}");
}

static void print_block_content(int blocknr)
{
	logger(LOG_DEBUG, "%s:%d:%s", __FILE__, __LINE__, __FUNCTION__);

	const void *restrict content = fetch_disk_block(blocknr);
	logger(LOG_DEBUG,
	       "======================== BLOCK NUMBER %d ========================",
	       blocknr);
	fwrite(content, blocksize, 1, stdout);
	fprintf(stderr, "\n");
	logger(LOG_DEBUG,
	       "======================== END BLOCK NUMBER %d ========================",
	       blocknr);
}

static void print_nilfs_info(const struct nilfs *nilfs)
{
	logger(LOG_DEBUG, "%s:%d:%s", __FILE__, __LINE__, __FUNCTION__);

	logger(LOG_DEBUG, "block_size = %ld", nilfs_get_block_size(nilfs));
	logger(LOG_DEBUG, "blocks_per_segment = %d",
	       nilfs_get_blocks_per_segment(nilfs));
	logger(LOG_DEBUG, "reserved_segments_ratio = %d",
	       nilfs_get_reserved_segments_ratio(nilfs));
	logger(LOG_DEBUG, "");
}

// ===============================================================================
// end of debug print functions
// ===============================================================================

// ===============================================================================
// hashtable
// ===============================================================================

#include <stddef.h>
#include <stdint.h>

struct hashtable_item {
	uint32_t key;
	void *value;
	size_t size;
};

struct hashtable_result {
	uint32_t count;
	struct hashtable_item **items;
};

struct hashtable {
	uint32_t size;
	uint32_t count;
	struct bucket **items;
};

enum hashtable_status { HASHTABLE_COLLISION, HASHTABLE_SUCCESS };

struct hashtable *hashtable_create(uint32_t size);
enum hashtable_status hashtable_put(struct hashtable *table, uint32_t key,
				    const void *value, size_t size);
struct hashtable_result *hashtable_get(const struct hashtable *table,
				       uint32_t key);
void hashtable_print(const struct hashtable *);

void hashtable_free(struct hashtable *);
void hashtable_result_free(struct hashtable_result *);

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

struct bucket {
	uint32_t size;
	uint32_t count;
	struct hashtable_item **items;
};

struct hashtable *hashtable_create(uint32_t size)
{
	assert(size > 0);

	struct hashtable *table = malloc(sizeof(struct hashtable));
	table->size = size;
	table->count = 0;
	table->items = calloc(table->size, sizeof(struct bucket));

	for (uint32_t i = 0; i < table->size; ++i)
		table->items[i] = NULL;

	return table;
}

static struct hashtable_item *create_item(uint32_t key, const void *value,
					  size_t size)
{
	struct hashtable_item *item = malloc(sizeof(struct hashtable_item));

	item->key = key;

	if (size > 0 && value) {
		item->value = malloc(size);
		item->size = size;
		memcpy(item->value, value, size);
	} else {
		item->value = NULL;
	}

	return item;
}

static uint32_t hash(const struct hashtable *table, uint32_t key)
{
	assert(table);
	return key % table->size;
}

static struct bucket *create_bucket_with_item(struct hashtable_item *item)
{
	assert(item);
	struct bucket *bucket = malloc(sizeof(struct bucket));

	bucket->count = 1;
	bucket->size = 1;
	bucket->items = calloc(1, sizeof(struct hashtable_item));
	bucket->items[0] = item;

	return bucket;
}

static bool bucket_contains_key(const struct bucket *bucket, uint32_t key)
{
	return bucket && bucket->count > 0 && bucket->items[0]->key == key;
}

enum hashtable_status hashtable_put(struct hashtable *table, uint32_t key,
				    const void *value, size_t size)
{
	assert(table);

	const uint32_t index = hash(table, key);
	struct bucket **current = &table->items[index];
	struct hashtable_item *item = create_item(key, value, size);

	if (bucket_contains_key(*current, key)) {
		const int count = (*current)->count;
		const int size = (*current)->size;
		if (count + 1 > size) {
			(*current)->items = realloc(
				(*current)->items,
				sizeof(struct hashtable_item) * (size + 1));
			(*current)->size++;
		}

		(*current)->items[count] = item;
		(*current)->count++;
		return HASHTABLE_COLLISION;
	}

	if (table->count < table->size) {
		*current = create_bucket_with_item(item);
		table->count++;
	} else {
		fprintf(stderr, "no space left in hashtable");
		exit(EXIT_FAILURE);
	}

	return HASHTABLE_SUCCESS;
}

uint32_t count_items_in_bucket_with_key(const struct bucket *bucket,
					uint32_t key)
{
	uint32_t count = 0;

	for (uint32_t i = 0; i < bucket->count; ++i) {
		assert(bucket->items[i]);

		if (bucket->items[i]->key == key) {
			count++;
		}
	}

	return count;
}

struct hashtable_result *hashtable_get(const struct hashtable *table,
				       uint32_t key)
{
	assert(table);
	assert(table->items);

	const uint32_t index = hash(table, key);
	const struct bucket *current = table->items[index];

	if (current == NULL || current->count == 0) {
		return NULL;
	}

	const uint32_t count = count_items_in_bucket_with_key(current, key);

	if (count == 0) {
		return NULL;
	}

	struct hashtable_item **items =
		calloc(count, sizeof(struct hashtable_item));

	for (uint32_t i = 0; i < count; ++i) {
		items[i] = malloc(sizeof(struct hashtable_item));
		items[i]->key = key;

		items[i]->value = malloc(current->items[i]->size);
		memcpy(items[i]->value, current->items[i]->value,
		       current->items[i]->size);
	}

	struct hashtable_result *result =
		malloc(sizeof(struct hashtable_result));
	result->count = count;
	result->items = items;

	return result;
}

static void print_item(const struct hashtable_item *item)
{
	fprintf(stderr, "KEY: %d, PTR: %p\n", item->key, item->value);
}

static void print_bucket(const struct bucket *bucket)
{
	for (uint32_t i = 0; i < bucket->count; ++i) {
		if (bucket->items[i])
			print_item(bucket->items[i]);
	}
}

void hashtable_print(const struct hashtable *table)
{
	for (uint32_t i = 0; i < table->size; ++i) {
		if (table->items[i])
			print_bucket(table->items[i]);
	}
}

static void free_item(struct hashtable_item *item)
{
	if (item) {
		if (item->value)
			free(item->value);

		free(item);
	}
}

static void free_bucket(struct bucket *bucket)
{
	if (bucket) {
		for (uint32_t i = 0; i < bucket->count; ++i) {
			free_item(bucket->items[i]);
		}

		free(bucket->items);
		free(bucket);
	}
}

void hashtable_result_free(struct hashtable_result *result)
{
	if (result) {
		for (uint32_t i = 0; i < result->count; ++i) {
			assert(result->items[i]);

			free_item(result->items[i]);
		}

		free(result->items);
		free(result);
	}
}

void hashtable_free(struct hashtable *table)
{
	if (table) {
		for (uint32_t i = 0; i < table->size; ++i) {
			struct bucket *bucket = table->items[i];

			if (bucket) {
				free_bucket(bucket);
			}
		}

		free(table->items);
		free(table);
	}
}

// ===============================================================================
// end of hashtable
// ===============================================================================

static uint32_t block_crc(int blocknr)
{
	logger(LOG_DEBUG, "%s:%d:%s", __FILE__, __LINE__, __FUNCTION__);

	if (dedup_options->verbose > 1)
		print_block_content(blocknr);

	const void *payload = fetch_disk_block(blocknr);
	const int crc_seed = 123;
	const uint32_t crc = nilfs_crc32(crc_seed, payload, blocksize);

	logger(LOG_DEBUG, "&&&&& CRC32 = %d &&&&&", crc);

	return crc;
}

struct block_info {
	uint64_t blocknr;
	uint32_t offset;
	uint32_t index;
	__le64 bd_offset;
	__le64 fi_ino;
	__u64 extent_length;
};

static bool block_extract_vdesc_success(const struct nilfs_file *file,
					const struct nilfs_block *block,
					struct nilfs_vdesc *vdesc)
{
	const ino_t ino = le64_to_cpu(file->finfo->fi_ino);

	// since we do not want to deduplicate DAT files, we exclude
	// them in earlier method, however if some error happens we
	// need to be sure (only DAT file uses real blocknr which can
	// compilicate stuff)
	if (ino < NILFS_USER_INO) {
		logger(LOG_INFO, "incorrect inode number %ld, skipping", ino);
		return false;
	}

	const nilfs_cno_t cno = le64_to_cpu(file->finfo->fi_cno);

	vdesc->vd_ino = ino;
	vdesc->vd_cno = cno;
	vdesc->vd_blocknr = block->blocknr;

	if (nilfs_block_is_data(block)) {
		const union nilfs_binfo *binfo = block->binfo;
		vdesc->vd_vblocknr = le64_to_cpu(binfo->bi_v.bi_vblocknr);
		vdesc->vd_offset = le64_to_cpu(binfo->bi_v.bi_blkoff);
		vdesc->vd_flags = 0; /* data */
		vdesc->vd_pad = 0;
		return true;
	}

	logger(LOG_INFO, "blocknr %ld is a node block, skipping",
	       block->blocknr);

	return false;
}

static bool block_empty(const struct nilfs_block *block)
{
	const char *payload = fetch_disk_block(block->blocknr);
	return strnlen(payload, blocksize) == 0;
}

static int populate_hashtable_with_segment_psegment_file_blocks(
	const struct nilfs_file *file, struct hashtable **table)
{
	struct nilfs_block block;

	nilfs_block_for_each(&block, file)
	{
		if (block_empty(&block)) {
			logger(LOG_DEBUG,
			       "skipping empty block with blocknr = %d",
			       block.blocknr);
			continue;
		}

		struct nilfs_vdesc vdesc;
		if (!block_extract_vdesc_success(file, &block, &vdesc)) {
			logger(LOG_WARNING,
			       "failed to extract vdesc block data from blocknr = %d",
			       block.blocknr);
			continue;
		}

		const uint32_t crc = block_crc(block.blocknr);
		logger(LOG_DEBUG,
		       "adding blocknr = %d, ino = %d, crc = %d to hashtable",
		       vdesc.vd_blocknr, vdesc.vd_ino, crc);

		hashtable_put(*table, crc, &vdesc, sizeof(vdesc));
	}

	return EXIT_SUCCESS;
}

static int populate_hashtable_with_segment_psegment_files(
	const struct nilfs_psegment *psegment, struct hashtable **table)
{
	struct nilfs_file file;
	nilfs_file_for_each(&file, psegment)
	{
		if (file.finfo->fi_ino < NILFS_USER_INO) {
			logger(LOG_DEBUG, "skipping special inode number: %d",
			       file.finfo->fi_ino);
			continue;
		}

		const int ret =
			populate_hashtable_with_segment_psegment_file_blocks(
				&file, table);

		if (ret) {
			logger(LOG_WARNING,
			       "failed to read psegment file blocks, file.ino = %ld, file.cno = %ld, psegment.blocknr = %d ",
			       file.finfo->fi_ino, file.finfo->fi_cno,
			       psegment->blocknr);
			continue;
		}
	}

	const char *errstr;
	if (nilfs_file_is_error(&file, &errstr)) {
		logger(LOG_WARNING,
		       "error %d (%s) while reading finfo at offset = %lu at pseg blocknr = %llu, segnum = %llu",
		       file.error, errstr, (unsigned long)file.offset,
		       (unsigned long long)psegment->blocknr,
		       (unsigned long long)psegment->segment->segnum);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int
populate_hashtable_with_segment_psegments(const struct nilfs_suinfo *si,
					  const struct nilfs_segment *segment,
					  struct hashtable **table)
{
	struct nilfs_psegment psegment;
	const int block_count = si->sui_nblocks;

	nilfs_psegment_for_each(&psegment, segment, block_count)
	{
		const int ret = populate_hashtable_with_segment_psegment_files(
			&psegment, table);
		if (ret) {
			logger(LOG_WARNING,
			       "failed to read psegment starting with blocknr %d",
			       psegment.blocknr);
			continue;
		}
	}

	const char *errstr;
	if (nilfs_psegment_is_error(&psegment, &errstr)) {
		logger(LOG_WARNING,
		       "error %d (%s) while reading segment summary at pseg blocknr = %llu, segnum = %llu",
		       psegment.error, errstr,
		       (unsigned long long)psegment.blocknr,
		       (unsigned long long)segment->segnum);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int populate_hashtable_with_segment(const struct nilfs *nilfs,
					   __u64 segment_number,
					   struct hashtable **table)
{
	struct nilfs_segment segment;
	struct nilfs_suinfo si;

	if (unlikely(nilfs_get_segment(nilfs, segment_number, &segment) < 0)) {
		logger(LOG_ERR, "cannot fetch segment");
		return EXIT_FAILURE;
	}

	if (unlikely(nilfs_get_suinfo(nilfs, segment_number, &si, 1) < 0)) {
		logger(LOG_ERR, "cannot fetch suinfo");
		return EXIT_FAILURE;
	}

	if (si.sui_nblocks == 0) {
		logger(LOG_WARNING, "segment %d is empty", segment_number);
		return EXIT_FAILURE;
	}

	logger(LOG_DEBUG, "SEGMENT NUMBER: %zu", segment_number);
	print_nilfs_suinfo(&si);
	print_nilfs_segment(&segment);

	const int ret =
		populate_hashtable_with_segment_psegments(&si, &segment, table);

	if (ret) {
		logger(LOG_WARNING,
		       "failed to populate hashtable with segment %d psegments",
		       segment_number);
		return ret;
	}

	if (unlikely(nilfs_put_segment(&segment))) {
		logger(LOG_ERR, "failed to release segment");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static __u64 get_dirty_segments(const struct nilfs *nilfs)
{
	struct nilfs_sustat sustat;
	nilfs_get_sustat(nilfs, &sustat);
	return sustat.ss_ndirtysegs;
}

static struct hashtable *populate_hashtable(const struct nilfs *nilfs)
{
	logger(LOG_DEBUG, "%s:%d:%s", __FILE__, __LINE__, __FUNCTION__);

	const __u64 nsegments = get_dirty_segments(nilfs);
	struct hashtable *table = hashtable_create(BUFFER_SIZE);
	if (!table) {
		logger(LOG_ERR, "cannot allocate hashtable: %s",
		       strerror(errno));
		exit(EXIT_FAILURE);
	}

	for (__u64 segment_number = 0; segment_number < nsegments;
	     ++segment_number) {
		if (segment_number % 100 == 0)
			logger(LOG_INFO,
			       "populating hashtable with segment %d of %d",
			       segment_number, nsegments);

		const int ret = populate_hashtable_with_segment(
			nilfs, segment_number, &table);

		if (ret) {
			logger(LOG_WARNING,
			       "failed to read segment %d, skipping",
			       segment_number);
			continue;
		}
	}

	return table;
}

static bool bucket_has_multiple_items(const struct bucket *bucket)
{
	logger(LOG_DEBUG, "%s:%d:%s bucket->count = %d > 1", __FILE__, __LINE__,
	       __FUNCTION__, bucket->count);

	return bucket->count > 1;
}

typedef struct nilfs_deduplication_payload deduplication_payload_t;

static void
fill_deduplication_payload(struct nilfs_deduplication_block *payload,
			   const struct nilfs_vdesc *info)
{
	payload->ino = info->vd_ino;
	payload->cno = info->vd_cno;
	payload->vblocknr = info->vd_vblocknr;
	payload->blocknr = info->vd_blocknr;
	payload->offset = info->vd_offset;
}

static const struct nilfs_vector *blocks_for_bucket(const struct bucket *bucket)
{
	logger(LOG_DEBUG, "%s:%d:%s", __FILE__, __LINE__, __FUNCTION__);

	assert(bucket);

	struct nilfs_vector *blocks =
		nilfs_vector_create(sizeof(struct nilfs_deduplication_block));

	for (size_t i = 0; i < bucket->count; ++i) {
		struct nilfs_deduplication_block *payload =
			nilfs_vector_get_new_element(blocks);
		const struct nilfs_vdesc *block = bucket->items[i]->value;

		fill_deduplication_payload(payload, block);
	}

	return blocks;
}

bool deduplication_payload_for_bucket(const struct bucket *bucket,
				      deduplication_payload_t **out)
{
	logger(LOG_DEBUG, "%s:%d:%s", __FILE__, __LINE__, __FUNCTION__);

	assert(*out);
	assert(bucket);

	const struct nilfs_vector *blocks = blocks_for_bucket(bucket);
	const size_t blocks_count = nilfs_vector_get_size(blocks);

	// at least two blocks to deduplicate needed in order to fill
	// src and destination files
	if (blocks_count < 2) {
		return false;
	}

	const struct nilfs_deduplication_block *src =
		nilfs_vector_get_element(blocks, 0);

	(*out)->src = *src;
	(*out)->dst_count = blocks_count - 1;
	(*out)->dst = malloc(sizeof(struct nilfs_deduplication_block) *
			     (*out)->dst_count);

	for (size_t i = 0; i < (*out)->dst_count; ++i) {
		const struct nilfs_deduplication_block *dst =
			nilfs_vector_get_element(blocks, i + 1);
		(*out)->dst[i] = *dst;
	}

	nilfs_vector_destroy((struct nilfs_vector *)blocks);

	return true;
}

static struct nilfs_deduplication_block *
convert_payload(const deduplication_payload_t *payload)
{
	const size_t count = payload->dst_count + 1;
	assert(count >= 2);

	struct nilfs_deduplication_block *blocks =
		malloc(sizeof(struct nilfs_deduplication_block) * count);

	blocks[0] = payload->src;

	for (size_t i = 1; i < count; ++i) {
		blocks[i] = payload->dst[i - 1];
	}

	return blocks;
}

static void deduplicate_payloads(const struct nilfs *nilfs,
				 const struct nilfs_vector *payloads)
{
	logger(LOG_DEBUG, "%s:%d:%s", __FILE__, __LINE__, __FUNCTION__);
	logger(LOG_INFO, "deduplicating %d payloads",
	       nilfs_vector_get_size(payloads));
	logger(LOG_INFO, "expected storage savings: %lld bytes",
	       nilfs_vector_get_size(payloads) * blocksize);

	if (dedup_options->dry_run) {
		logger(LOG_INFO, "end of dry run, exiting");
		return;
	}

	for (size_t i = 0; i < nilfs_vector_get_size(payloads); ++i) {
		if (i % 100 == 0)
			logger(LOG_INFO, "Deduplicating payload %d of %d", i,
			       nilfs_vector_get_size(payloads));

		const deduplication_payload_t *payload =
			nilfs_vector_get_element(payloads, i);

		struct nilfs_deduplication_block *converted_payload =
			convert_payload(payload);
		if (nilfs_dedup(nilfs, converted_payload,
				payload->dst_count + 1) < 0) {
			logger(LOG_ERR, "cannot call ioctl: %s",
			       strerror(errno));
		}
		free(converted_payload);
	}
}

static void free_payloads(struct nilfs_vector *payloads)
{
	logger(LOG_DEBUG, "%s:%d:%s", __FILE__, __LINE__, __FUNCTION__);

	for (size_t i = 0; i < nilfs_vector_get_size(payloads); ++i) {
		const deduplication_payload_t *payload =
			nilfs_vector_get_element(payloads, i);
		free(payload->dst);
	}

	nilfs_vector_destroy(payloads);
}

static struct nilfs_vector *obtain_payloads(const struct hashtable *table)
{
	logger(LOG_DEBUG, "%s:%d:%s", __FILE__, __LINE__, __FUNCTION__);

	struct nilfs_vector *payloads =
		nilfs_vector_create(sizeof(deduplication_payload_t));

	for (size_t i = 0; i < table->size; ++i) {
		const struct bucket *bucket = table->items[i];

		if (bucket && bucket_has_multiple_items(bucket)) {
			deduplication_payload_t *payload =
				nilfs_vector_get_new_element(payloads);

			if (!deduplication_payload_for_bucket(bucket,
							      &payload)) {
				logger(LOG_WARNING,
				       "cannot prepare payload for blocks with crc: '%d'",
				       bucket->items[0]->key);
				nilfs_vector_delete_element(
					payloads,
					nilfs_vector_get_size(payloads) - 1);
			}
		}
	}

	return payloads;
}

static void
print_deduplication_block(const struct nilfs_deduplication_block *block)
{
	logger(LOG_DEBUG, "%s:%d:%s", __FILE__, __LINE__, __FUNCTION__);
	logger(LOG_DEBUG,
	       "				nilfs_deduplication_block = { ino = %ld, blocknr = %ld }",
	       block->ino, block->blocknr);
}

static void print_deduplication_payloads(const struct nilfs_vector *payloads)
{
	logger(LOG_DEBUG, "%s:%d:%s", __FILE__, __LINE__, __FUNCTION__);

	logger(LOG_DEBUG, "deduplication_payloads: {");

	for (size_t i = 0; i < nilfs_vector_get_size(payloads); ++i) {
		logger(LOG_DEBUG,
		       "	struct nilfs_deduplication_payload {");
		const deduplication_payload_t *payload =
			nilfs_vector_get_element(payloads, i);
		logger(LOG_DEBUG, "		src = {");
		print_deduplication_block(&payload->src);
		logger(LOG_DEBUG, "		}");

		logger(LOG_DEBUG, "		dst_count = %ld",
		       payload->dst_count);
		logger(LOG_DEBUG, "		dst = [");

		for (size_t j = 0; j < payload->dst_count; ++j) {
			print_deduplication_block(&payload->dst[j]);
		}

		logger(LOG_DEBUG, "		]");
		logger(LOG_DEBUG, "	}");
	}

	logger(LOG_DEBUG, "}");
}

static void deduplicate(const struct nilfs *restrict nilfs)
{
	logger(LOG_DEBUG, "%s:%d:%s", __FILE__, __LINE__, __FUNCTION__);

	struct hashtable *crc_table = NULL;
	struct nilfs_vector *deduplication_payloads = NULL;

	while (true) {
		crc_table = populate_hashtable(nilfs);
		deduplication_payloads = obtain_payloads(crc_table);

		if (nilfs_vector_get_size(deduplication_payloads) != 0) {
			break;
		}

		logger(LOG_WARNING,
		       "couldn't obtain deduplication payloads, waiting ...");
		free_payloads(deduplication_payloads);
		hashtable_free(crc_table);
		sleep(1);
	}

	print_deduplication_payloads(deduplication_payloads);

	deduplicate_payloads(nilfs, deduplication_payloads);

	free_payloads((struct nilfs_vector *)deduplication_payloads);
	hashtable_free((struct hashtable *)crc_table);
}

int run(const char *dev, const struct dedup_options *options)
{
	device = dev;
	dedup_options = options;

	logger(LOG_DEBUG, "%s:%d:%s", __FILE__, __LINE__, __FUNCTION__);

	init_disk_buffer();
	fetch_disk_buffer(0);

	struct nilfs *fs = nilfs_open_safe(device);
	nilfs_opt_set_mmap(fs);

	print_nilfs_layout(fs);
	print_nilfs_sustat(fs);
	print_nilfs_info(fs);

	deduplicate(fs);

	nilfs_close(fs);

	return EXIT_SUCCESS;
}