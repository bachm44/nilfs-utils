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
#include <math.h>

#undef NDEBUG

#define BUFFER_SIZE 1000000
#define MAX_FILES 4096
#define MAX_FILE_DESCRIPTORS 256

#define nilfs_crc32(seed, data, length) crc32_le(seed, data, length)



// ===============================================================================
// logging
// ===============================================================================

static void default_logger(int priority, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);
}

static void (*nilfs_dedup_logger)(int priority, const char *fmt, ...) = default_logger;

// ===============================================================================
// end of logging
// ===============================================================================



// ===============================================================================
// disk_buffer
// ===============================================================================

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

static void fetch_disk_buffer(const char* restrict device)
{
	const int fd = open(device, O_RDWR);
	if (unlikely(fd < 0)) {
		printf("error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	lseek(fd, 0, SEEK_SET);
	for (size_t i = 0; i < 512; ++i) {
		if(read(fd, map_disk_buffer(i, 0), blocksize) < 0) {
			printf("error: %s\n", strerror(errno));
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

static struct nilfs* nilfs_open_safe(const char* restrict device)
{
	struct nilfs *nilfs =
		nilfs_open(device, NULL, NILFS_OPEN_RDWR | NILFS_OPEN_RAW);
	if (nilfs) {
		nilfs_dedup_logger(LOG_INFO, "nilfs opened");
	} else {
		nilfs_dedup_logger(LOG_ERR, "error: cannot open fs: %s", strerror(errno));
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

static void print_nilfs_suinfo(const struct nilfs_suinfo* si) 
{
	printf("nilfs_suinfo {\n");
	printf("	nblocks = %d\n", si->sui_nblocks);
	printf("	lastmod = %lld\n", si->sui_lastmod);
	printf("}\n\n");
}

static void print_nilfs_segment(const struct nilfs_segment* segment)
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

static void print_nilfs_layout(const struct nilfs* nilfs)
{
	struct nilfs_layout layout;
	nilfs_get_layout(nilfs, &layout, sizeof(struct nilfs_layout));

	printf("nilfs_layout {\n");
	printf("	rev_level = %d\n", layout.rev_level);
	printf("	minor_rev_level = %d\n", layout.minor_rev_level);
	printf("	flags = %d\n", layout.flags);
	printf("	blocksize_bits = %d\n", layout.blocksize_bits);
	printf("	blocksize = %d\n", layout.blocksize);
	printf("	devsize = %ld\n", layout.devsize);
	printf("	crc_seed = %d\n", layout.crc_seed);
	printf("	pad = %d\n", layout.pad);
	printf("	nsegments = %ld\n", layout.nsegments);
	printf("	blocks_per_segment = %d\n", layout.blocks_per_segment);
	printf("	reserved_segments_ratio = %d\n", layout.reserved_segments_ratio);
	printf("	first_segment_blkoff = %ld\n", layout.first_segment_blkoff);
	printf("	feature_compat = %ld\n", layout.feature_compat);
	printf("	feature_compat_ro = %ld\n", layout.feature_compat_ro);
	printf("	feature_incompat = %ld\n", layout.feature_incompat);
	printf("}\n\n");
}

static void print_nilfs_sustat(const struct nilfs* nilfs)
{
	struct nilfs_sustat sustat;

	nilfs_get_sustat(nilfs, &sustat);

	printf("nilfs_sustat {\n");
	printf("	ss_nsegs = %lld\n", sustat.ss_nsegs);
	printf("	ss_ncleansegs = %lld\n", sustat.ss_ncleansegs);
	printf("	ss_ndirtysegs = %lld\n", sustat.ss_ndirtysegs);
	printf("	ss_ctime = %lld\n", sustat.ss_ctime);
	printf("	ss_nongc_ctime = %lld\n", sustat.ss_nongc_ctime);
	printf("	ss_prot_seq = %lld\n", sustat.ss_prot_seq);
	printf("}\n\n");
}

static void print_block_content(int blocknr)
{
	const void* restrict content = map_disk_buffer(blocknr, 0);
	printf("======================== BLOCK NUMBER %d ========================\n", blocknr);
	fwrite(content, blocksize, 1, stdout);
	printf("\n======================== END BLOCK NUMBER %d ========================\n", blocknr);
}

static void print_nilfs_info(const struct nilfs* nilfs)
{
	printf("block_size = %ld\n", nilfs_get_block_size(nilfs));
	printf("blocks_per_segment = %d\n", nilfs_get_blocks_per_segment(nilfs));
	printf("reserved_segments_ratio = %d\n", nilfs_get_reserved_segments_ratio(nilfs));
	printf("\n");
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
		fprintf(stderr, "no space left in hashtable\n");
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

// ===============================================================================
// single-linked list
// ===============================================================================

#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <stdbool.h>
#include <stddef.h>

struct list {
	void *data;
	size_t data_size;
	struct list *next;
};

struct list *list_new(void *data, size_t size);
void list_add(struct list *head, void *data, size_t size);
void list_free(struct list *);

#endif

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

struct list *list_new(void *data, size_t size)
{
	struct list *result = malloc(sizeof(struct list));

	result->data = malloc(size);
	memcpy(result->data, data, size);
	result->data_size = size;
	result->next = NULL;

	return result;
}

void list_add(struct list *list, void *data, size_t size)
{
	struct list *tmp = list;
	while (tmp->next) {
		tmp = tmp->next;
	}

	tmp->next = list_new(data, size);
}

void list_free(struct list *list)
{
	struct list *temp = NULL;
	struct list *head = list;

	while (head != NULL) {
		temp = head;
		head = head->next;
		free(temp->data);
		free(temp);
	}
}

// ===============================================================================
// end of single-linked list
// ===============================================================================

uint32_t block_crc(int blocknr)
{
	print_block_content(blocknr);
	const void *payload = map_disk_buffer(blocknr, 0);
	const int crc_seed = 123;
	const uint32_t crc = nilfs_crc32(crc_seed, payload, blocksize);

	printf("&&&&& CRC32 = %d &&&&& \n\n", crc);

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

static __le64 block_bd_offset(const struct nilfs_block* blk, const struct nilfs_file* file)
{
	union nilfs_binfo *binfo;
	if (nilfs_file_use_real_blocknr(file)) {
		if (nilfs_block_is_data(blk)) {
			return le64_to_cpu(*(__le64 *) blk->binfo);
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

struct hashtable* populate_hashtable_with_block_crc(const struct nilfs* nilfs)
{
	const int nsegments = nilfs_get_nsegments(nilfs);
	struct hashtable *table = hashtable_create(BUFFER_SIZE);
	if (table == NULL) {
		nilfs_dedup_logger(LOG_ERR, "error: cannot allocate hashtable: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct nilfs_suinfo si;

	for (size_t segment_number = 0; segment_number < nsegments; ++segment_number)
	{
		struct nilfs_segment segment;

		if(unlikely(nilfs_get_segment(nilfs, segment_number, &segment) < 0)) {
			nilfs_dedup_logger(LOG_ERR, "error: cannot fetch segment");
			exit(EXIT_FAILURE);
		}

		if(unlikely(nilfs_get_suinfo(nilfs, segment_number, &si, 1) < 0)) {
			nilfs_dedup_logger(LOG_ERR, "error: cannot fetch suinfo");
			exit(EXIT_FAILURE);
		}

		if (si.sui_nblocks == 0) {
			continue;
		}

		printf("SEGMENT NUMBER: %zu\n",segment_number);
		print_nilfs_suinfo(&si);
		print_nilfs_segment(&segment);

		struct nilfs_psegment psegment;
		const int block_count = si.sui_nblocks;

		nilfs_psegment_for_each(&psegment, &segment, block_count) {
			struct nilfs_file file;

			nilfs_file_for_each(&file, &psegment) {
				struct nilfs_block block;

				nilfs_block_for_each(&block, &file) {
					const uint32_t crc = block_crc(block.blocknr);
					const struct block_info info = {
						.blocknr = block.blocknr,
						.offset = block.offset,
						.index = block.index,
						.bd_offset = block_bd_offset(&block, &file),
						.fi_ino = block.file->finfo->fi_ino,
						.extent_length = BLOCK_SIZE
					};
					hashtable_put(table, crc, &info, sizeof(struct block_info));
				}
			}
		}

		if (unlikely(nilfs_put_segment(&segment))) {
			printf("failed to release segment\n");
		}
	}

	assert(table);
	return table;
}

static struct hashtable* inode_info;

struct inode_info {
	const char* filename;
	off_t st_size;
};

int visit_entry(const char *__filename,
				  const struct stat *__status, int __flag)
{
	// process only files
	if (__flag == FTW_F) {
		printf("FILENAME: %s, %ld\n", __filename, __status->st_ino);
		const struct inode_info info = {.filename = __filename, .st_size = __status->st_size};
		hashtable_put(inode_info, __status->st_ino, &info, sizeof(struct inode_info));
	}

	return 0;
}

void create_inode_filename_mapping(const struct nilfs* restrict nilfs)
{
	const char* mountpoint = nilfs_get_ioc(nilfs);
	inode_info = hashtable_create(MAX_FILES);
	ftw(mountpoint, visit_entry, MAX_FILE_DESCRIPTORS);
}

bool bucket_has_multiple_items(const struct bucket* bucket)
{
	return bucket->count > 1;
}

struct deduplication_payload {
	int src_fd;
	const struct file_dedupe_range* dedupe_range;
};

int file_descriptor_for_block(const struct block_info* info)
{
	const struct hashtable_result* entry = hashtable_get(inode_info, info->fi_ino);

	if (!entry) {
		printf("cannot find inode with number: %lld\n", info->fi_ino);
		return -1;
	}

	assert(entry->count == 1);

	const struct inode_info* inode = entry->items[0]->value;
	const char* name = inode->filename;

	const int fd = open(name, O_RDONLY);

	if (fd < 0) {
		printf("cannot open file '%s': %s\n", name, strerror(errno));
	}

	hashtable_result_free((struct hashtable_result*) entry);

	return fd;
}

off_t real_size_for_block(const struct block_info* info)
{
	const struct hashtable_result* entry = hashtable_get(inode_info, info->fi_ino);

	if (!entry) {
		printf("cannot find inode with number: %lld\n", info->fi_ino);
		return -1;
	}

	assert(entry->count == 1);

	const struct inode_info* inode = entry->items[0]->value;
	const off_t size = inode->st_size;

	hashtable_result_free((struct hashtable_result*) entry);
	return size;
}

struct extent_info {
	__s64 fd;
	__u64 offset;
	__u64 length;
};

const struct nilfs_vector* extents_for_bucket(const struct bucket* bucket)
{
	assert(bucket);

	struct nilfs_vector* extents = nilfs_vector_create(sizeof(struct extent_info));

	for (size_t i = 0; i < bucket->count; ++i) {
		struct extent_info* extent = nilfs_vector_get_new_element(extents);
		const struct block_info* block = bucket->items[i]->value;

		const int fd = file_descriptor_for_block(block);

		if (fd <= 0) {
			nilfs_vector_delete_element(extents, nilfs_vector_get_size(extents) - 1);
			continue;
		}

		extent->fd = fd;
		extent->offset = block->bd_offset;
		extent->length = fmin((double) real_size_for_block(block), (double) block->extent_length);
	}

	return extents;
}

bool deduplication_payload_for_bucket(const struct bucket* bucket, struct deduplication_payload** out)
{
	const struct nilfs_vector* extents = extents_for_bucket(bucket);
	const size_t extents_size = nilfs_vector_get_size(extents);

	// at least two blocks to deduplicate needed in order to fill
	// src and destination files in file_dedupe_range
	if (extents_size < 2) {
		return false;
	}

	const struct extent_info* src = nilfs_vector_get_element(extents, 0);
	(*out)->src_fd = src->fd;

	const size_t range_size = sizeof(struct file_dedupe_range) + sizeof(struct file_dedupe_range_info) * (extents_size - 1);
	struct file_dedupe_range* range = calloc(1, range_size);

	range->src_offset = src->offset;
	range->src_length = src->length;
	range->dest_count = extents_size - 1;

	for (size_t i = 1; i < extents_size; ++i) {
		const struct extent_info* extent = nilfs_vector_get_element(extents, i);
		range->info[i - 1].dest_fd = extent->fd;
		range->info[i - 1].dest_offset = extent->offset;
	}

	(*out)->dedupe_range = range;

	nilfs_vector_destroy((struct nilfs_vector*) extents);

	return true;
}

int deduplicate_ioctl(const struct deduplication_payload* payload)
{
	return ioctl(payload->src_fd, FIDEDUPERANGE, payload->dedupe_range);
}

void deduplicate_payloads(const struct nilfs_vector* payloads)
{
	for (size_t i = 0; i < nilfs_vector_get_size(payloads); ++i) {
		const struct deduplication_payload* payload = nilfs_vector_get_element(payloads, i);

		if (deduplicate_ioctl(payload) == -1) {
			printf("cannot call FIDEDUPERANGE ioctl: %s\n", strerror(errno));
		}
	}
}

void free_fd(int fd)
{
	printf("close fd: %d\n", fd);
	if (close(fd) != 0) {
		printf("cannot free fd %d: %s\n", fd, strerror(errno));
	}
}

void free_payloads(struct nilfs_vector* payloads)
{
	for (size_t i = 0; i < nilfs_vector_get_size(payloads); ++i) {
		const struct deduplication_payload* payload = nilfs_vector_get_element(payloads, i);
		free_fd(payload->src_fd);

		const int dest_count = payload->dedupe_range->dest_count;
		for (size_t j = 0; j < dest_count; ++j) {
			free_fd(payload->dedupe_range->info[j].dest_fd);
		}

		free((void*) payload->dedupe_range);
	}

	nilfs_vector_destroy(payloads);
}

const struct nilfs_vector* obtain_payloads(const struct hashtable* table)
{
	struct nilfs_vector* payloads = nilfs_vector_create(sizeof(struct deduplication_payload));

	for (size_t i = 0; i < table->size; ++i) {
		const struct bucket* bucket = table->items[i];

		if (bucket && bucket_has_multiple_items(bucket)) {
			assert(bucket->count < MAX_FILE_DESCRIPTORS);

			struct deduplication_payload* payload = nilfs_vector_get_new_element(payloads);

			if (!deduplication_payload_for_bucket(bucket, &payload)) {
				printf("cannot prepare payload for blocks with crc: '%d'\n", bucket->items[0]->key);
				nilfs_vector_delete_element(payloads, nilfs_vector_get_size(payloads) - 1);
			}
		}
	}

	return payloads;
}

void print_dedupe_range_info(const struct file_dedupe_range_info info[], int count)
{
	for (size_t i = 0; i < count; ++i) {
		printf("			{\n");
		printf("				dest_fd = %lld\n", info[i].dest_fd);
		printf("				dest_offset = %lld\n", info[i].dest_offset);
		printf("			},\n");
	}
}

void print_dedupe_range(const struct file_dedupe_range* range)
{
	printf("		src_offset = %lld\n", range->src_offset);
	printf("		src_length = %lld\n", range->src_length);
	printf("		dest_count = %d\n", range->dest_count);
	printf("		info = [\n");
	print_dedupe_range_info(range->info, range->dest_count);
	printf("		]\n");
}

void print_deduplication_payloads(const struct nilfs_vector* payloads)
{
	printf("deduplication_payloads: {\n");

	for (size_t i = 0; i < nilfs_vector_get_size(payloads); ++i) {
		printf("struct deduplication_payload {\n");
		const struct deduplication_payload *payload =
			nilfs_vector_get_element(payloads, i);
		printf("	src_fd = %d\n", payload->src_fd);
		printf("	dedupe_range = {\n");
		print_dedupe_range(payload->dedupe_range);
		printf("	}\n");
	}

	printf("}\n");
}

void deduplicate(const struct nilfs* restrict nilfs)
{
	const struct hashtable* restrict crc_table = populate_hashtable_with_block_crc(nilfs);
	hashtable_print(crc_table);

	const struct nilfs_vector* deduplication_payloads = obtain_payloads(crc_table);
	print_deduplication_payloads(deduplication_payloads);

	deduplicate_payloads(deduplication_payloads);

	free_payloads((struct nilfs_vector*) deduplication_payloads);
	hashtable_free((struct hashtable*) crc_table);
}

int run(const char* restrict device)
{
	init_disk_buffer(BUFFER_SIZE);
	fetch_disk_buffer(device);

	struct nilfs* fs = nilfs_open_safe(device);
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