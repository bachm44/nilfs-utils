#include "dedup.h"
#include "nilfs.h"
#include "perr.h"
#include "util.h"
#include "vector.h"
#include "crc32.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syslog.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

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

// ===============================================================================
// end of disk_buffer
// ===============================================================================


// ===============================================================================
// nilfs utils
// ===============================================================================

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

static void print_nilfs_info(struct nilfs* nilfs)
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

#include <stdint.h>

struct hashtable_item {
	uint32_t key;
	uint32_t value;
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

struct hashtable *hashtable_create(uint32_t size);
void hashtable_put(struct hashtable *, uint32_t key, uint32_t value);
struct hashtable_result *hashtable_get(const struct hashtable *, uint32_t key);
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

static struct hashtable_item *create_item(uint32_t key, uint32_t value)
{
	struct hashtable_item *item = malloc(sizeof(struct hashtable_item));

	item->key = key;
	item->value = value;

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

void hashtable_put(struct hashtable *table, uint32_t key, uint32_t value)
{
	assert(table);

	const uint32_t index = hash(table, key);
	struct bucket **current = &table->items[index];
	struct hashtable_item *item = create_item(key, value);

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
	} else {
		if (table->count < table->size) {
			*current = create_bucket_with_item(item);
			table->count++;
		} else {
			fprintf(stderr, "no space left in hashtable\n");
			exit(EXIT_FAILURE);
		}
	}
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

	uint32_t count = 0;

	for (uint32_t i = 0; i < current->count; ++i) {
		assert(current->items[i]);

		if (current->items[i]->key == key) {
			count++;
		}
	}

	if (count == 0) {
		return NULL;
	}

	struct hashtable_item **items =
		calloc(count, sizeof(struct hashtable_item));

	for (uint32_t i = 0; i < count; ++i) {
		items[i] = malloc(sizeof(struct hashtable_item));
		items[i] = memcpy(items[i], current->items[i],
				  sizeof(struct hashtable_item));
	}

	struct hashtable_result *result =
		malloc(sizeof(struct hashtable_result));
	result->count = count;
	result->items = items;

	return result;
}

static void print_item(const struct hashtable_item *item)
{
	fprintf(stderr, "KEY: %d, VALUE: %d\n", item->key, item->value);
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
	printf("TABLE_SIZE = %d, TABLE_COUNT = %d\n", table->size, table->count);
	for (uint32_t i = 0; i < table->size; ++i) {
		if (table->items[i])
			print_bucket(table->items[i]);
	}
}

static void free_item(struct hashtable_item *item)
{
	if (item)
		free(item);
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

#define BUFFER_SIZE 1000000

void run()
{
	init_disk_buffer(BUFFER_SIZE);
	fetch_disk_buffer();

	struct nilfs* nilfs = nilfs_open_safe();

	print_nilfs_layout(nilfs);
	print_nilfs_sustat(nilfs);
	print_nilfs_info(nilfs);

	struct nilfs_vector *bdescv =
		nilfs_vector_create(sizeof(struct nilfs_bdesc));
	struct nilfs_vector *vdescv = nilfs_vector_create(sizeof(struct nilfs_vdesc));

	if (!bdescv || !vdescv) {
		nilfs_dedup_logger(LOG_ERR, "error: cannot allocate vector: %s", strerror(errno));
		exit(1);
	}

	const int nsegments = nilfs_get_nsegments(nilfs);

	struct hashtable *table = hashtable_create(BUFFER_SIZE);
	if (table == NULL) {
		nilfs_dedup_logger(LOG_ERR, "error: cannot allocate hashtable: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct nilfs_suinfo si;

	for (size_t segment_number = 0; segment_number < nsegments; ++segment_number)
	{
		struct nilfs_segment *segment = malloc(sizeof(struct nilfs_segment));

		if(unlikely(nilfs_get_segment(nilfs, segment_number, segment) < 0)) {
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
		print_nilfs_segment(segment);

		const int block_start = segment->blocknr;
		const int block_end = block_start + si.sui_nblocks;

		for (int blocknr = block_start; blocknr < block_end; ++blocknr) {
			print_block_content(blocknr);
			const void *payload = map_disk_buffer(blocknr, 0);
			const int crc_seed = 123;
			const uint32_t crc = nilfs_crc32(crc_seed, payload, blocksize);

			printf("&&&&& CRC32 = %d &&&&& \n\n", crc);

			hashtable_put(table, crc, blocknr);
		}

		nilfs_segment_free(segment);
	}

	hashtable_print(table);
	hashtable_free(table);

	nilfs_close(nilfs);
	nilfs_vector_destroy(bdescv);
	nilfs_vector_destroy(vdescv);
}