#include "dedup.h"
#include "nilfs.h"
#include "perr.h"
#include "util.h"
#include "vector.h"
#include "crc32.h"
#include "segment.h"

#include <ftw.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syslog.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

#undef NDEBUG

#define BUFFER_SIZE 1000000
#define MAX_FILES 4096
#define MAX_FILE_DESCRIPTORS 256

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
static unsigned long disk_buffer_size;

#define NILFS_DEF_BLOCKSIZE_BITS \
	12 /* default blocksize = 2^12
						bytes */
#define NILFS_DEF_BLOCKSIZE (1 << NILFS_DEF_BLOCKSIZE_BITS)

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

static void fetch_disk_buffer(const char *restrict device)
{
	const int fd = open(device, O_RDWR);
	if (unlikely(fd < 0)) {
		logger(LOG_ERR, "cannot fetch disk buffer: %s",
		       strerror(errno));
		exit(EXIT_FAILURE);
	}

	lseek(fd, 0, SEEK_SET);
	for (size_t i = 0; i < 512; ++i) {
		if (read(fd, map_disk_buffer(i, 0), blocksize) < 0) {
			logger(LOG_ERR,
			       "cannot map disk buffer for fd = %d, blocksize = %lld: %s",
			       fd, blocksize, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
}

// ===============================================================================
// end of disk_buffer
// ===============================================================================

// ===============================================================================
// nilfs utils
// ===============================================================================

static struct nilfs *nilfs_open_safe(const char *restrict device)
{
	struct nilfs *nilfs =
		nilfs_open(device, NULL, NILFS_OPEN_RDWR | NILFS_OPEN_RAW);
	if (nilfs) {
		logger(LOG_INFO, "nilfs opened");
	} else {
		logger(LOG_ERR, "cannot open fs: %s", strerror(errno));
		exit(1);
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
	logger(LOG_DEBUG, "nilfs_suinfo {");
	logger(LOG_DEBUG, "	nblocks = %d", si->sui_nblocks);
	logger(LOG_DEBUG, "	lastmod = %lld", si->sui_lastmod);
	logger(LOG_DEBUG, "}");
}

static void print_nilfs_segment(const struct nilfs_segment *segment)
{
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
	const void *restrict content = map_disk_buffer(blocknr, 0);
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
	for (int i = 0; i < bucket->count; ++i) {
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
		for (uint32_t i = 0; i < table->count; ++i) {
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

uint32_t block_crc(int blocknr)
{
	if (dedup_options->verbose > 1)
		print_block_content(blocknr);

	const void *payload = map_disk_buffer(blocknr, 0);
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

static __le64 block_bd_offset(const struct nilfs_block *blk,
			      const struct nilfs_file *file)
{
	union nilfs_binfo *binfo;
	if (nilfs_file_use_real_blocknr(file)) {
		if (nilfs_block_is_data(blk)) {
			return le64_to_cpu(*(__le64 *)blk->binfo);
		} else {
			binfo = blk->binfo;
			return le64_to_cpu(binfo->bi_dat.bi_blkoff);
		}
	} else {
		if (nilfs_block_is_data(blk)) {
			binfo = blk->binfo;
			return le64_to_cpu(binfo->bi_v.bi_blkoff);
		} else {
			return le64_to_cpu(*(__le64 *)blk->binfo);
		}
	}
}

struct hashtable *populate_hashtable_with_block_crc(const struct nilfs *nilfs)
{
	const int nsegments = nilfs_get_nsegments(nilfs);
	struct hashtable *table = hashtable_create(BUFFER_SIZE);
	if (table == NULL) {
		logger(LOG_ERR, "cannot allocate hashtable: %s",
		       strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct nilfs_suinfo si;

	for (size_t segment_number = 0; segment_number < nsegments;
	     ++segment_number) {
		struct nilfs_segment segment;

		if (unlikely(nilfs_get_segment(nilfs, segment_number,
					       &segment) < 0)) {
			logger(LOG_ERR, "cannot fetch segment");
			exit(EXIT_FAILURE);
		}

		if (unlikely(nilfs_get_suinfo(nilfs, segment_number, &si, 1) <
			     0)) {
			logger(LOG_ERR, "cannot fetch suinfo");
			exit(EXIT_FAILURE);
		}

		if (si.sui_nblocks == 0) {
			continue;
		}

		logger(LOG_DEBUG, "SEGMENT NUMBER: %zu", segment_number);
		print_nilfs_suinfo(&si);
		print_nilfs_segment(&segment);

		struct nilfs_psegment psegment;
		const int block_count = si.sui_nblocks;

		nilfs_psegment_for_each(&psegment, &segment, block_count)
		{
			struct nilfs_file file;

			nilfs_file_for_each(&file, &psegment)
			{
				struct nilfs_block block;

				nilfs_block_for_each(&block, &file)
				{
					const uint32_t crc =
						block_crc(block.blocknr);
					const struct block_info info = {
						.blocknr = block.blocknr,
						.offset = block.offset,
						.index = block.index,
						.bd_offset = block_bd_offset(
							&block, &file),
						.fi_ino = block.file->finfo
								  ->fi_ino,
						.extent_length = BLOCK_SIZE
					};
					hashtable_put(
						table, crc, &info,
						sizeof(struct block_info));
				}
			}
		}

		if (unlikely(nilfs_put_segment(&segment))) {
			logger(LOG_ERR, "failed to release segment");
		}
	}

	assert(table);
	return table;
}

static struct hashtable *inode_info;

struct inode_info {
	off_t st_size;
	char filename[FILENAME_MAX];
};

int visit_entry(const char *__filename, const struct stat *__status, int __flag)
{
	// process only files
	if (__flag == FTW_F) {
		logger(LOG_INFO, "VISITING FILENAME: %s, %ld", __filename,
		       __status->st_ino);

		struct inode_info info;
		info.st_size = __status->st_size;
		strncpy(info.filename, __filename, strlen(__filename) + 1);

		hashtable_put(inode_info, __status->st_ino, &info,
			      sizeof(struct inode_info));
	}

	return 0;
}

void create_inode_filename_mapping(const struct nilfs *restrict nilfs)
{
	const char *mountpoint = nilfs_get_ioc(nilfs);
	inode_info = hashtable_create(MAX_FILES);
	ftw(mountpoint, visit_entry, MAX_FILE_DESCRIPTORS);
}

bool bucket_has_multiple_items(const struct bucket *bucket)
{
	return bucket->count > 1;
}

struct deduplication_payload {
	int src_fd;
	const struct file_dedupe_range *dedupe_range;
};

int file_descriptor_for_block(const struct block_info *info)
{
	const struct hashtable_result *entry =
		hashtable_get(inode_info, info->fi_ino);

	if (!entry) {
		logger(LOG_WARNING, "cannot find inode with number: %lld",
		       info->fi_ino);
		return -1;
	}

	assert(entry->count == 1);

	const struct inode_info *inode = entry->items[0]->value;
	const char *name = inode->filename;

	const int fd = open(name, O_RDONLY);
	logger(LOG_INFO, "opening file '%s' with fd = %d", name, fd);

	if (fd < 0) {
		logger(LOG_WARNING, "cannot open file '%s': %s", name,
		       strerror(errno));
	}

	hashtable_result_free((struct hashtable_result *)entry);

	return fd;
}

off_t real_size_for_block(const struct block_info *info)
{
	const struct hashtable_result *entry =
		hashtable_get(inode_info, info->fi_ino);

	if (!entry) {
		logger(LOG_WARNING, "cannot find inode with number: %lld",
		       info->fi_ino);
		return -1;
	}

	assert(entry->count == 1);

	const struct inode_info *inode = entry->items[0]->value;
	const off_t size = inode->st_size;

	hashtable_result_free((struct hashtable_result *)entry);
	return size;
}

struct extent_info {
	__s64 fd;
	__u64 offset;
	__u64 length;
};

int min(int a, int b)
{
	return (b < a) ? b : a;
}

const struct nilfs_vector *extents_for_bucket(const struct bucket *bucket)
{
	assert(bucket);

	struct nilfs_vector *extents =
		nilfs_vector_create(sizeof(struct extent_info));

	for (size_t i = 0; i < bucket->count; ++i) {
		struct extent_info *extent =
			nilfs_vector_get_new_element(extents);
		const struct block_info *block = bucket->items[i]->value;

		const int fd = file_descriptor_for_block(block);

		if (fd <= 0) {
			nilfs_vector_delete_element(
				extents, nilfs_vector_get_size(extents) - 1);
			continue;
		}

		extent->fd = fd;
		extent->offset = block->bd_offset;
		extent->length =
			min(real_size_for_block(block), block->extent_length);
	}

	return extents;
}

bool deduplication_payload_for_bucket(const struct bucket *bucket,
				      struct deduplication_payload **out)
{
	const struct nilfs_vector *extents = extents_for_bucket(bucket);
	const size_t extents_size = nilfs_vector_get_size(extents);

	// at least two blocks to deduplicate needed in order to fill
	// src and destination files in file_dedupe_range
	if (extents_size < 2) {
		return false;
	}

	const struct extent_info *src = nilfs_vector_get_element(extents, 0);
	(*out)->src_fd = src->fd;

	const size_t range_size =
		sizeof(struct file_dedupe_range) +
		sizeof(struct file_dedupe_range_info) * (extents_size - 1);
	struct file_dedupe_range *range = calloc(1, range_size);

	range->src_offset = src->offset;
	range->src_length = src->length;
	range->dest_count = extents_size - 1;

	for (size_t i = 1; i < extents_size; ++i) {
		const struct extent_info *extent =
			nilfs_vector_get_element(extents, i);
		range->info[i - 1].dest_fd = extent->fd;
		range->info[i - 1].dest_offset = extent->offset;
	}

	(*out)->dedupe_range = range;

	nilfs_vector_destroy((struct nilfs_vector *)extents);

	return true;
}

int deduplicate_ioctl(const struct deduplication_payload *payload)
{
	return ioctl(payload->src_fd, FIDEDUPERANGE, payload->dedupe_range);
}

void deduplicate_payloads(const struct nilfs_vector *payloads)
{
	for (size_t i = 0; i < nilfs_vector_get_size(payloads); ++i) {
		const struct deduplication_payload *payload =
			nilfs_vector_get_element(payloads, i);

		if (deduplicate_ioctl(payload) == -1) {
			logger(LOG_ERR, "cannot call FIDEDUPERANGE ioctl: %s",
			       strerror(errno));
		}
	}
}

void free_fd(int fd)
{
	logger(LOG_INFO, "close fd: %d", fd);
	if (close(fd) != 0) {
		logger(LOG_WARNING, "cannot free fd %d: %s", fd,
		       strerror(errno));
	}
}

void free_payloads(struct nilfs_vector *payloads)
{
	for (size_t i = 0; i < nilfs_vector_get_size(payloads); ++i) {
		const struct deduplication_payload *payload =
			nilfs_vector_get_element(payloads, i);
		free_fd(payload->src_fd);

		const int dest_count = payload->dedupe_range->dest_count;
		for (size_t j = 0; j < dest_count; ++j) {
			free_fd(payload->dedupe_range->info[j].dest_fd);
		}

		free((void *)payload->dedupe_range);
	}

	nilfs_vector_destroy(payloads);
}

const struct nilfs_vector *obtain_payloads(const struct hashtable *table)
{
	struct nilfs_vector *payloads =
		nilfs_vector_create(sizeof(struct deduplication_payload));

	for (size_t i = 0; i < table->size; ++i) {
		const struct bucket *bucket = table->items[i];

		if (bucket && bucket_has_multiple_items(bucket)) {
			assert(bucket->count < MAX_FILE_DESCRIPTORS);

			struct deduplication_payload *payload =
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

void print_dedupe_range_info(const struct file_dedupe_range_info info[],
			     int count)
{
	for (size_t i = 0; i < count; ++i) {
		logger(LOG_INFO, "			{");
		logger(LOG_INFO,
		       "				dest_fd = %lld",
		       info[i].dest_fd);
		logger(LOG_INFO,
		       "				dest_offset = %lld",
		       info[i].dest_offset);
		logger(LOG_INFO, "			},");
	}
}

void print_dedupe_range(const struct file_dedupe_range *range)
{
	logger(LOG_INFO, "		src_offset = %lld", range->src_offset);
	logger(LOG_INFO, "		src_length = %lld", range->src_length);
	logger(LOG_INFO, "		dest_count = %d", range->dest_count);
	logger(LOG_INFO, "		info = [");
	print_dedupe_range_info(range->info, range->dest_count);
	logger(LOG_INFO, "		]");
}

void print_deduplication_payloads(const struct nilfs_vector *payloads)
{
	logger(LOG_INFO, "deduplication_payloads: {");

	for (size_t i = 0; i < nilfs_vector_get_size(payloads); ++i) {
		logger(LOG_INFO, "	struct deduplication_payload {");
		const struct deduplication_payload *payload =
			nilfs_vector_get_element(payloads, i);
		logger(LOG_INFO, "		src_fd = %d", payload->src_fd);
		logger(LOG_INFO, "		dedupe_range = {");
		print_dedupe_range(payload->dedupe_range);
		logger(LOG_INFO, "	}");
	}

	logger(LOG_INFO, "}");
}

void deduplicate(const struct nilfs *restrict nilfs)
{
	const struct hashtable *restrict crc_table =
		populate_hashtable_with_block_crc(nilfs);

	const struct nilfs_vector *deduplication_payloads =
		obtain_payloads(crc_table);

	print_deduplication_payloads(deduplication_payloads);

	deduplicate_payloads(deduplication_payloads);

	free_payloads((struct nilfs_vector *)deduplication_payloads);
	hashtable_free((struct hashtable *)crc_table);
}

int run(const char *restrict device, const struct dedup_options *options)
{
	dedup_options = options;

	init_disk_buffer(BUFFER_SIZE);
	fetch_disk_buffer(device);

	struct nilfs *fs = nilfs_open_safe(device);
	nilfs_opt_set_mmap(fs);

	print_nilfs_layout(fs);
	print_nilfs_sustat(fs);
	print_nilfs_info(fs);

	create_inode_filename_mapping(fs);
	deduplicate(fs);
	hashtable_free(inode_info);

	nilfs_close(fs);

	return EXIT_SUCCESS;
}