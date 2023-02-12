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

// ===============================================================================
// http://pokristensson.com/code/strmap/strmap.h
// ===============================================================================

/*
 *    strmap version 2.0.1
 *
 *    ANSI C hash table for strings.
 *
 *	  Version history:
 *	  1.0.0 - initial release
 *	  2.0.0 - changed function prefix from strmap to sm to ensure
 *	      ANSI C compatibility
 *	  2.0.1 - improved documentation 
 *
 *    strmap.h
 *
 *    Copyright (c) 2009, 2011, 2013 Per Ola Kristensson.
 *
 *    Per Ola Kristensson <pok21@cam.ac.uk> 
 *    Inference Group, Department of Physics
 *    University of Cambridge
 *    Cavendish Laboratory
 *    JJ Thomson Avenue
 *    CB3 0HE Cambridge
 *    United Kingdom
 *
 *    strmap is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU Lesser General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    strmap is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU Lesser General Public License for more details.
 *
 *    You should have received a copy of the GNU Lesser General Public License
 *    along with strmap.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef _STRMAP_H_
#define _STRMAP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <string.h>

typedef struct StrMap StrMap;

/*
 * This callback function is called once per key-value when iterating over
 * all keys associated to values.
 *
 * Parameters:
 *
 * key: A pointer to a null-terminated C string. The string must not
 * be modified by the client.
 *
 * value: A pointer to a null-terminated C string. The string must
 * not be modified by the client.
 *
 * obj: A pointer to a client-specific object. This parameter may be
 * null.
 *
 * Return value: None.
 */
typedef void (*sm_enum_func)(const char *key, const char *value,
			     const void *obj);

/*
 * Creates a string map.
 *
 * Parameters:
 *
 * capacity: The number of top-level slots this string map
 * should allocate. This parameter must be > 0.
 *
 * Return value: A pointer to a string map object, 
 * or null if a new string map could not be allocated.
 */
StrMap *sm_new(unsigned int capacity);

/*
 * Releases all memory held by a string map object.
 *
 * Parameters:
 *
 * map: A pointer to a string map. This parameter cannot be null.
 * If the supplied string map has been previously released, the
 * behaviour of this function is undefined.
 *
 * Return value: None.
 */
void sm_delete(StrMap *map);

/*
 * Returns the value associated with the supplied key.
 *
 * Parameters:
 *
 * map: A pointer to a string map. This parameter cannot be null.
 *
 * key: A pointer to a null-terminated C string. This parameter cannot
 * be null.
 *
 * out_buf: A pointer to an output buffer which will contain the value,
 * if it exists and fits into the buffer.
 *
 * n_out_buf: The size of the output buffer in bytes.
 *
 * Return value: If out_buf is set to null and n_out_buf is set to 0 the return
 * value will be the number of bytes required to store the value (if it exists)
 * and its null-terminator. For all other parameter configurations the return value
 * is 1 if an associated value was found and completely copied into the output buffer,
 * 0 otherwise.
 */
int sm_get(const StrMap *map, const char *key, char *out_buf,
	   unsigned int n_out_buf);

/*
 * Queries the existence of a key.
 *
 * Parameters:
 *
 * map: A pointer to a string map. This parameter cannot be null.
 *
 * key: A pointer to a null-terminated C string. This parameter cannot
 * be null.
 *
 * Return value: 1 if the key exists, 0 otherwise.
 */
int sm_exists(const StrMap *map, const char *key);

/*
 * Associates a value with the supplied key. If the key is already
 * associated with a value, the previous value is replaced.
 *
 * Parameters:
 *
 * map: A pointer to a string map. This parameter cannot be null.
 *
 * key: A pointer to a null-terminated C string. This parameter
 * cannot be null. The string must have a string length > 0. The
 * string will be copied.
 *
 * value: A pointer to a null-terminated C string. This parameter
 * cannot be null. The string must have a string length > 0. The
 * string will be copied.
 *
 * Return value: 1 if the association succeeded, 0 otherwise.
 */
int sm_put(StrMap *map, const char *key, const char *value);

/*
 * Returns the number of associations between keys and values.
 *
 * Parameters:
 *
 * map: A pointer to a string map. This parameter cannot be null.
 *
 * Return value: The number of associations between keys and values.
 */
int sm_get_count(const StrMap *map);

/*
 * An enumerator over all associations between keys and values.
 *
 * Parameters:
 *
 * map: A pointer to a string map. This parameter cannot be null.
 *
 * enum_func: A pointer to a callback function that will be
 * called by this procedure once for every key associated
 * with a value. This parameter cannot be null.
 *
 * obj: A pointer to a client-specific object. This parameter will be
 * passed back to the client's callback function. This parameter can
 * be null.
 *
 * Return value: 1 if enumeration completed, 0 otherwise.
 */
int sm_enum(const StrMap *map, sm_enum_func enum_func, const void *obj);

#ifdef __cplusplus
}
#endif

#endif

/*

		   GNU LESSER GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.


  This version of the GNU Lesser General Public License incorporates
the terms and conditions of version 3 of the GNU General Public
License, supplemented by the additional permissions listed below.

  0. Additional Definitions.

  As used herein, "this License" refers to version 3 of the GNU Lesser
General Public License, and the "GNU GPL" refers to version 3 of the GNU
General Public License.

  "The Library" refers to a covered work governed by this License,
other than an Application or a Combined Work as defined below.

  An "Application" is any work that makes use of an interface provided
by the Library, but which is not otherwise based on the Library.
Defining a subclass of a class defined by the Library is deemed a mode
of using an interface provided by the Library.

  A "Combined Work" is a work produced by combining or linking an
Application with the Library.  The particular version of the Library
with which the Combined Work was made is also called the "Linked
Version".

  The "Minimal Corresponding Source" for a Combined Work means the
Corresponding Source for the Combined Work, excluding any source code
for portions of the Combined Work that, considered in isolation, are
based on the Application, and not on the Linked Version.

  The "Corresponding Application Code" for a Combined Work means the
object code and/or source code for the Application, including any data
and utility programs needed for reproducing the Combined Work from the
Application, but excluding the System Libraries of the Combined Work.

  1. Exception to Section 3 of the GNU GPL.

  You may convey a covered work under sections 3 and 4 of this License
without being bound by section 3 of the GNU GPL.

  2. Conveying Modified Versions.

  If you modify a copy of the Library, and, in your modifications, a
facility refers to a function or data to be supplied by an Application
that uses the facility (other than as an argument passed when the
facility is invoked), then you may convey a copy of the modified
version:

   a) under this License, provided that you make a good faith effort to
   ensure that, in the event an Application does not supply the
   function or data, the facility still operates, and performs
   whatever part of its purpose remains meaningful, or

   b) under the GNU GPL, with none of the additional permissions of
   this License applicable to that copy.

  3. Object Code Incorporating Material from Library Header Files.

  The object code form of an Application may incorporate material from
a header file that is part of the Library.  You may convey such object
code under terms of your choice, provided that, if the incorporated
material is not limited to numerical parameters, data structure
layouts and accessors, or small macros, inline functions and templates
(ten or fewer lines in length), you do both of the following:

   a) Give prominent notice with each copy of the object code that the
   Library is used in it and that the Library and its use are
   covered by this License.

   b) Accompany the object code with a copy of the GNU GPL and this license
   document.

  4. Combined Works.

  You may convey a Combined Work under terms of your choice that,
taken together, effectively do not restrict modification of the
portions of the Library contained in the Combined Work and reverse
engineering for debugging such modifications, if you also do each of
the following:

   a) Give prominent notice with each copy of the Combined Work that
   the Library is used in it and that the Library and its use are
   covered by this License.

   b) Accompany the Combined Work with a copy of the GNU GPL and this license
   document.

   c) For a Combined Work that displays copyright notices during
   execution, include the copyright notice for the Library among
   these notices, as well as a reference directing the user to the
   copies of the GNU GPL and this license document.

   d) Do one of the following:

       0) Convey the Minimal Corresponding Source under the terms of this
       License, and the Corresponding Application Code in a form
       suitable for, and under terms that permit, the user to
       recombine or relink the Application with a modified version of
       the Linked Version to produce a modified Combined Work, in the
       manner specified by section 6 of the GNU GPL for conveying
       Corresponding Source.

       1) Use a suitable shared library mechanism for linking with the
       Library.  A suitable mechanism is one that (a) uses at run time
       a copy of the Library already present on the user's computer
       system, and (b) will operate properly with a modified version
       of the Library that is interface-compatible with the Linked
       Version.

   e) Provide Installation Information, but only if you would otherwise
   be required to provide such information under section 6 of the
   GNU GPL, and only to the extent that such information is
   necessary to install and execute a modified version of the
   Combined Work produced by recombining or relinking the
   Application with a modified version of the Linked Version. (If
   you use option 4d0, the Installation Information must accompany
   the Minimal Corresponding Source and Corresponding Application
   Code. If you use option 4d1, you must provide the Installation
   Information in the manner specified by section 6 of the GNU GPL
   for conveying Corresponding Source.)

  5. Combined Libraries.

  You may place library facilities that are a work based on the
Library side by side in a single library together with other library
facilities that are not Applications and are not covered by this
License, and convey such a combined library under terms of your
choice, if you do both of the following:

   a) Accompany the combined library with a copy of the same work based
   on the Library, uncombined with any other library facilities,
   conveyed under the terms of this License.

   b) Give prominent notice with the combined library that part of it
   is a work based on the Library, and explaining where to find the
   accompanying uncombined form of the same work.

  6. Revised Versions of the GNU Lesser General Public License.

  The Free Software Foundation may publish revised and/or new versions
of the GNU Lesser General Public License from time to time. Such new
versions will be similar in spirit to the present version, but may
differ in detail to address new problems or concerns.

  Each version is given a distinguishing version number. If the
Library as you received it specifies that a certain numbered version
of the GNU Lesser General Public License "or any later version"
applies to it, you have the option of following the terms and
conditions either of that published version or of any later version
published by the Free Software Foundation. If the Library as you
received it does not specify a version number of the GNU Lesser
General Public License, you may choose any version of the GNU Lesser
General Public License ever published by the Free Software Foundation.

  If the Library as you received it specifies that a proxy can decide
whether future versions of the GNU Lesser General Public License shall
apply, that proxy's public statement of acceptance of any version is
permanent authorization for you to choose that version for the
Library.

*/


// ===============================================================================
// http://pokristensson.com/code/strmap/strmap.c
// ===============================================================================

/*
 *    strmap version 2.0.1
 *
 *    ANSI C hash table for strings.
 *
 *	  Version history:
 *	  1.0.0 - initial release
 *	  2.0.0 - changed function prefix from strmap to sm to ensure
 *	      ANSI C compatibility 
 *	  2.0.1 - improved documentation 
 *
 *    strmap.c
 *
 *    Copyright (c) 2009, 2011, 2013 Per Ola Kristensson.
 *
 *    Per Ola Kristensson <pok21@cam.ac.uk> 
 *    Inference Group, Department of Physics
 *    University of Cambridge
 *    Cavendish Laboratory
 *    JJ Thomson Avenue
 *    CB3 0HE Cambridge
 *    United Kingdom
 *
 *    strmap is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU Lesser General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    strmap is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU Lesser General Public License for more details.
 *
 *    You should have received a copy of the GNU Lesser General Public License
 *    along with strmap.  If not, see <http://www.gnu.org/licenses/>.
 */

typedef struct Pair Pair;

typedef struct Bucket Bucket;

struct Pair {
	char *key;
	char *value;
};

struct Bucket {
	unsigned int count;
	Pair *pairs;
};

struct StrMap {
	unsigned int count;
	Bucket *buckets;
};

static Pair *get_pair(Bucket *bucket, const char *key);
static unsigned long hash(const char *str);

StrMap *sm_new(unsigned int capacity)
{
	StrMap *map;

	map = malloc(sizeof(StrMap));
	if (map == NULL) {
		return NULL;
	}
	map->count = capacity;
	map->buckets = malloc(map->count * sizeof(Bucket));
	if (map->buckets == NULL) {
		free(map);
		return NULL;
	}
	memset(map->buckets, 0, map->count * sizeof(Bucket));
	return map;
}

void sm_delete(StrMap *map)
{
	unsigned int i, j, n, m;
	Bucket *bucket;
	Pair *pair;

	if (map == NULL) {
		return;
	}
	n = map->count;
	bucket = map->buckets;
	i = 0;
	while (i < n) {
		m = bucket->count;
		pair = bucket->pairs;
		j = 0;
		while (j < m) {
			free(pair->key);
			free(pair->value);
			pair++;
			j++;
		}
		free(bucket->pairs);
		bucket++;
		i++;
	}
	free(map->buckets);
	free(map);
}

int sm_get(const StrMap *map, const char *key, char *out_buf,
	   unsigned int n_out_buf)
{
	unsigned int index;
	Bucket *bucket;
	Pair *pair;

	if (map == NULL) {
		return 0;
	}
	if (key == NULL) {
		return 0;
	}
	index = hash(key) % map->count;
	bucket = &(map->buckets[index]);
	pair = get_pair(bucket, key);
	if (pair == NULL) {
		return 0;
	}
	if (out_buf == NULL && n_out_buf == 0) {
		return strlen(pair->value) + 1;
	}
	if (out_buf == NULL) {
		return 0;
	}
	if (strlen(pair->value) >= n_out_buf) {
		return 0;
	}
	strcpy(out_buf, pair->value);
	return 1;
}

int sm_exists(const StrMap *map, const char *key)
{
	unsigned int index;
	Bucket *bucket;
	Pair *pair;

	if (map == NULL) {
		return 0;
	}
	if (key == NULL) {
		return 0;
	}
	index = hash(key) % map->count;
	bucket = &(map->buckets[index]);
	pair = get_pair(bucket, key);
	if (pair == NULL) {
		return 0;
	}
	return 1;
}

int sm_put(StrMap *map, const char *key, const char *value)
{
	unsigned int key_len, value_len, index;
	Bucket *bucket;
	Pair *tmp_pairs, *pair;
	char *tmp_value;
	char *new_key, *new_value;

	if (map == NULL) {
		return 0;
	}
	if (key == NULL || value == NULL) {
		return 0;
	}
	key_len = strlen(key);
	value_len = strlen(value);
	/* Get a pointer to the bucket the key string hashes to */
	index = hash(key) % map->count;
	bucket = &(map->buckets[index]);
	/* Check if we can handle insertion by simply replacing
	 * an existing value in a key-value pair in the bucket.
	 */
	if ((pair = get_pair(bucket, key)) != NULL) {
		/* The bucket contains a pair that matches the provided key,
		 * change the value for that pair to the new value.
		 */
		if (strlen(pair->value) < value_len) {
			/* If the new value is larger than the old value, re-allocate
			 * space for the new larger value.
			 */
			tmp_value = realloc(pair->value,
					    (value_len + 1) * sizeof(char));
			if (tmp_value == NULL) {
				return 0;
			}
			pair->value = tmp_value;
		}
		/* Copy the new value into the pair that matches the key */
		strcpy(pair->value, value);
		return 1;
	}
	/* Allocate space for a new key and value */
	new_key = malloc((key_len + 1) * sizeof(char));
	if (new_key == NULL) {
		return 0;
	}
	new_value = malloc((value_len + 1) * sizeof(char));
	if (new_value == NULL) {
		free(new_key);
		return 0;
	}
	/* Create a key-value pair */
	if (bucket->count == 0) {
		/* The bucket is empty, lazily allocate space for a single
		 * key-value pair.
		 */
		bucket->pairs = malloc(sizeof(Pair));
		if (bucket->pairs == NULL) {
			free(new_key);
			free(new_value);
			return 0;
		}
		bucket->count = 1;
	} else {
		/* The bucket wasn't empty but no pair existed that matches the provided
		 * key, so create a new key-value pair.
		 */
		tmp_pairs = realloc(bucket->pairs,
				    (bucket->count + 1) * sizeof(Pair));
		if (tmp_pairs == NULL) {
			free(new_key);
			free(new_value);
			return 0;
		}
		bucket->pairs = tmp_pairs;
		bucket->count++;
	}
	/* Get the last pair in the chain for the bucket */
	pair = &(bucket->pairs[bucket->count - 1]);
	pair->key = new_key;
	pair->value = new_value;
	/* Copy the key and its value into the key-value pair */
	strcpy(pair->key, key);
	strcpy(pair->value, value);
	return 1;
}

int sm_get_count(const StrMap *map)
{
	unsigned int i, j, n, m;
	unsigned int count;
	Bucket *bucket;
	Pair *pair;

	if (map == NULL) {
		return 0;
	}
	bucket = map->buckets;
	n = map->count;
	i = 0;
	count = 0;
	while (i < n) {
		pair = bucket->pairs;
		m = bucket->count;
		j = 0;
		while (j < m) {
			count++;
			pair++;
			j++;
		}
		bucket++;
		i++;
	}
	return count;
}

int sm_enum(const StrMap *map, sm_enum_func enum_func, const void *obj)
{
	unsigned int i, j, n, m;
	Bucket *bucket;
	Pair *pair;

	if (map == NULL) {
		return 0;
	}
	if (enum_func == NULL) {
		return 0;
	}
	bucket = map->buckets;
	n = map->count;
	i = 0;
	while (i < n) {
		pair = bucket->pairs;
		m = bucket->count;
		j = 0;
		while (j < m) {
			enum_func(pair->key, pair->value, obj);
			pair++;
			j++;
		}
		bucket++;
		i++;
	}
	return 1;
}

/*
 * Returns a pair from the bucket that matches the provided key,
 * or null if no such pair exist.
 */
static Pair *get_pair(Bucket *bucket, const char *key)
{
	unsigned int i, n;
	Pair *pair;

	n = bucket->count;
	if (n == 0) {
		return NULL;
	}
	pair = bucket->pairs;
	i = 0;
	while (i < n) {
		if (pair->key != NULL && pair->value != NULL) {
			if (strcmp(pair->key, key) == 0) {
				return pair;
			}
		}
		pair++;
		i++;
	}
	return NULL;
}

/*
 * Returns a hash code for the provided string.
 */
static unsigned long hash(const char *str)
{
	unsigned long hash = 5381;
	int c;

	while (c = *str++) {
		hash = ((hash << 5) + hash) + c;
	}
	return hash;
}

/*

		   GNU LESSER GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.


  This version of the GNU Lesser General Public License incorporates
the terms and conditions of version 3 of the GNU General Public
License, supplemented by the additional permissions listed below.

  0. Additional Definitions.

  As used herein, "this License" refers to version 3 of the GNU Lesser
General Public License, and the "GNU GPL" refers to version 3 of the GNU
General Public License.

  "The Library" refers to a covered work governed by this License,
other than an Application or a Combined Work as defined below.

  An "Application" is any work that makes use of an interface provided
by the Library, but which is not otherwise based on the Library.
Defining a subclass of a class defined by the Library is deemed a mode
of using an interface provided by the Library.

  A "Combined Work" is a work produced by combining or linking an
Application with the Library.  The particular version of the Library
with which the Combined Work was made is also called the "Linked
Version".

  The "Minimal Corresponding Source" for a Combined Work means the
Corresponding Source for the Combined Work, excluding any source code
for portions of the Combined Work that, considered in isolation, are
based on the Application, and not on the Linked Version.

  The "Corresponding Application Code" for a Combined Work means the
object code and/or source code for the Application, including any data
and utility programs needed for reproducing the Combined Work from the
Application, but excluding the System Libraries of the Combined Work.

  1. Exception to Section 3 of the GNU GPL.

  You may convey a covered work under sections 3 and 4 of this License
without being bound by section 3 of the GNU GPL.

  2. Conveying Modified Versions.

  If you modify a copy of the Library, and, in your modifications, a
facility refers to a function or data to be supplied by an Application
that uses the facility (other than as an argument passed when the
facility is invoked), then you may convey a copy of the modified
version:

   a) under this License, provided that you make a good faith effort to
   ensure that, in the event an Application does not supply the
   function or data, the facility still operates, and performs
   whatever part of its purpose remains meaningful, or

   b) under the GNU GPL, with none of the additional permissions of
   this License applicable to that copy.

  3. Object Code Incorporating Material from Library Header Files.

  The object code form of an Application may incorporate material from
a header file that is part of the Library.  You may convey such object
code under terms of your choice, provided that, if the incorporated
material is not limited to numerical parameters, data structure
layouts and accessors, or small macros, inline functions and templates
(ten or fewer lines in length), you do both of the following:

   a) Give prominent notice with each copy of the object code that the
   Library is used in it and that the Library and its use are
   covered by this License.

   b) Accompany the object code with a copy of the GNU GPL and this license
   document.

  4. Combined Works.

  You may convey a Combined Work under terms of your choice that,
taken together, effectively do not restrict modification of the
portions of the Library contained in the Combined Work and reverse
engineering for debugging such modifications, if you also do each of
the following:

   a) Give prominent notice with each copy of the Combined Work that
   the Library is used in it and that the Library and its use are
   covered by this License.

   b) Accompany the Combined Work with a copy of the GNU GPL and this license
   document.

   c) For a Combined Work that displays copyright notices during
   execution, include the copyright notice for the Library among
   these notices, as well as a reference directing the user to the
   copies of the GNU GPL and this license document.

   d) Do one of the following:

       0) Convey the Minimal Corresponding Source under the terms of this
       License, and the Corresponding Application Code in a form
       suitable for, and under terms that permit, the user to
       recombine or relink the Application with a modified version of
       the Linked Version to produce a modified Combined Work, in the
       manner specified by section 6 of the GNU GPL for conveying
       Corresponding Source.

       1) Use a suitable shared library mechanism for linking with the
       Library.  A suitable mechanism is one that (a) uses at run time
       a copy of the Library already present on the user's computer
       system, and (b) will operate properly with a modified version
       of the Library that is interface-compatible with the Linked
       Version.

   e) Provide Installation Information, but only if you would otherwise
   be required to provide such information under section 6 of the
   GNU GPL, and only to the extent that such information is
   necessary to install and execute a modified version of the
   Combined Work produced by recombining or relinking the
   Application with a modified version of the Linked Version. (If
   you use option 4d0, the Installation Information must accompany
   the Minimal Corresponding Source and Corresponding Application
   Code. If you use option 4d1, you must provide the Installation
   Information in the manner specified by section 6 of the GNU GPL
   for conveying Corresponding Source.)

  5. Combined Libraries.

  You may place library facilities that are a work based on the
Library side by side in a single library together with other library
facilities that are not Applications and are not covered by this
License, and convey such a combined library under terms of your
choice, if you do both of the following:

   a) Accompany the combined library with a copy of the same work based
   on the Library, uncombined with any other library facilities,
   conveyed under the terms of this License.

   b) Give prominent notice with the combined library that part of it
   is a work based on the Library, and explaining where to find the
   accompanying uncombined form of the same work.

  6. Revised Versions of the GNU Lesser General Public License.

  The Free Software Foundation may publish revised and/or new versions
of the GNU Lesser General Public License from time to time. Such new
versions will be similar in spirit to the present version, but may
differ in detail to address new problems or concerns.

  Each version is given a distinguishing version number. If the
Library as you received it specifies that a certain numbered version
of the GNU Lesser General Public License "or any later version"
applies to it, you have the option of following the terms and
conditions either of that published version or of any later version
published by the Free Software Foundation. If the Library as you
received it does not specify a version number of the GNU Lesser
General Public License, you may choose any version of the GNU Lesser
General Public License ever published by the Free Software Foundation.

  If the Library as you received it specifies that a proxy can decide
whether future versions of the GNU Lesser General Public License shall
apply, that proxy's public statement of acceptance of any version is
permanent authorization for you to choose that version for the
Library.

*/

// ===============================================================================
// end of hashtable
// ===============================================================================

static void sm_print_key_value(const char *key, const char *value, const void *obj)
{
	printf("key: %s value: %s\n", key, value);
}

static void sm_print(const StrMap* restrict map)
{
	printf("SM: {\n");
	sm_enum(map, sm_print_key_value, NULL);
	printf("\n\n");
}

void run()
{
	init_disk_buffer(1000000);
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

	StrMap *map = sm_new(1);
	if (map == NULL) {
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

			const int crc_length = snprintf(NULL, 0, "%d", crc) + 1;
			char* restrict crc_str = malloc(crc_length);
			snprintf(crc_str, crc_length, "%d", crc);

			printf("&&&&& CRC32 = %s &&&&& \n\n", crc_str);

			const int blocknr_length = snprintf(NULL, 0, "%d", blocknr) + 1;
			char* restrict blocknr_str = malloc(blocknr_length);
			snprintf(blocknr_str, blocknr_length, "%d", blocknr);

			sm_put(map, crc_str, blocknr_str);
			free(crc_str);
			free(blocknr_str);

		}

		nilfs_segment_free(segment);
	}

	sm_print(map);
	sm_delete(map);

	nilfs_close(nilfs);
	nilfs_vector_destroy(bdescv);
	nilfs_vector_destroy(vdescv);
}