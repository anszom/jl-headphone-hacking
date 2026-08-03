/* 
 * Filesystem hooks.
 * 
 * This module hooks a FAT iteration function: f_readnextdir in order to implement directory-level sorting. The
 * initial bytes of f_readnextdir are patched into a jump to our hook. A corresponding trampoline in trampoline.S
 * allows us to call the original function.
 *
 * Also included: a missing file_ftell implementation
 *
 */
#include "system/event.h"
#include "system/fs/fs.h"
#include "asm/br36.h"

#include "fs_private.h"
#include "debug.h"
#include "patcher.h"

int f_readnextdir_trampoline(FATFS* fs, DIR *dj, DIRINFO *dirinfo, FS_NAME *pathbuf);

#define MAX_ENTRIES (64)

/*
 * Directory-level sorting.
 * f_readnextdir iterates over a directory using a `DIR` structure. For easier handling, we have redefined the structure
 * into an 'identity' and 'iterator' part, while maintaining binary compatibility with the SDK version.
 *
 * Upon entering a directory, we enumerate all the files (up to MAX_ENTRIES) and sort the iterators. We return our own
 * higher-level iterator, which contains an index into the sorted array. Internally, we pick the lower iterator from
 * the array and forward it to the lower f_readnextdir. All happens transparently to the caller.
 *
 * If a directory listing exceeds MAX_ENTRIES, we fall back to unsorted operation.
 *
 * We try to use LFN filenames for sorting if they are available. Binary collation only.
 *
 */
static u32 sclust_loaded=~0;
static DIR_ITER entries[MAX_ENTRIES];
static int entries_total = 0;

// f_opendir initializes the 'iterator' part to the first entry of the directory
void f_opendir(FATFS *fs, DIR *dj);

void wdt_clr();

// Preallocated storage for two LFN filenames. More may be allocated off the heap at runtime. If heap space runs low,
// we fall-back to a low-memory solution, trading I/O & execution time for memory.
static unsigned short lfn_buf1[256], lfn_buf2[256];

// Because of memory constraints, the iterators & filenames don't need to be allocated together, that's why most
// functions here take two arrays or two sets of arguments.
static int compare(const unsigned short *a, const DIR_ITER *ait, const unsigned short *b, const DIR_ITER *bit)
{
	int c;

	// compare lfn
	for(c=0;c<256;c++) {
		unsigned short ac = a[c];
		unsigned short bc = b[c];
		if(ac < bc)
			return -1;
		if(ac > bc)
			return 1;

		if(!ac && !bc)
			break;
	}

	// stable tie-break
	return memcmp(ait, bit, sizeof(DIR_ITER));
}

// swaps two entries of (DIR_ITER, unsigned short*) pairwise
static void swap(DIR_ITER *e0, unsigned short **p0, DIR_ITER *e1, unsigned short **p1)
{
	DIR_ITER tmp;
	memcpy(&tmp, e0, sizeof(DIR_ITER));
	memcpy(e0, e1, sizeof(DIR_ITER));
	memcpy(e1, &tmp, sizeof(DIR_ITER));

	unsigned short *ptmp;
	ptmp = *p0;
	*p0 = *p1;
	*p1 = ptmp;
}

struct dir_context {
	FATFS *fs;
	DIR_ID *id;
};

// SDK function
int lfn_decode(unsigned short * lfn_buf, int lfn_cnt);

// our wrapper, falls back to an expanded 8.3 filename
static int filename_decode(unsigned short *lfn_buf, int lfn_cnt, const unsigned char *p83)
{
	int rv = lfn_decode(lfn_buf, lfn_cnt);
	if(rv > 0) {
		int i;
		for(i=0;;i++) {
			if(i == 255) {
				lfn_buf[i] = 0;
				break;
			}
			if(lfn_buf[i] == 0)
				break;
		}

		return i;
	} else {
		int i=0;
		int j=0;
		for(i=0;i<8;i++) {
			if(p83[i]<=' ')
				break;
			lfn_buf[j++] = p83[i];
		}

		if(p83[8]>' ') {
			lfn_buf[j++] = '.';
			for(i=8;i<11;i++) {
				if(p83[i]<=' ')
					break;
				lfn_buf[j++] = p83[i];
			}
		}
		lfn_buf[j] = 0;
		return j;
	}
}

// Returns a pre-loaded LFN filename if it's available, otherwise loads it from storage into `buf`.
// This unifies the happy & low-memory solutions.
static unsigned short *load_filename(struct dir_context *context, unsigned short *name, DIR_ITER *entry, unsigned short *buf)
{
	// happy path: use in-memory filename
	if(name)
		return name;

	// OOM path: load filename from disk into a scratch buffer
	FS_NAME my_pathbuf = {0};
	my_pathbuf.lfn = buf;

	wdt_clr();
	DIR dj;
	DIRINFO dirinfo;
	memcpy(&dj.id, context->id, sizeof(DIR_ID));
	memcpy(&dj.iter, entry, sizeof(DIR_ITER));
	int rv = f_readnextdir_trampoline(context->fs, &dj, &dirinfo, &my_pathbuf);
	if(rv >= 130) {
		buf[0] = 0;
		return buf;
	}

	// decode LFN/SFN path into utf-16
	filename_decode(buf, my_pathbuf.lfn_cnt, dirinfo.fname);
	return buf;
}

// Standard-ish quicksort, but operates on two parallel arrays: `entry` & `names`
// `names` may contain null entries if memory was not available, missing filenames will be loaded
// at runtime.
static void quicksort(struct dir_context *context, DIR_ITER *entry, unsigned short **names, int count)
{
	for(;;) {
		if(count <= 1)
			return;

		int pivot = count/2;
		// put the pivot at the beginning
		swap(entry, names, entry+pivot, names+pivot);

		unsigned short *pivot_name = load_filename(context, names[0], entry, lfn_buf1);
		int lt = 1, gt = count-1;
		while(lt <= gt) {
			unsigned short *entry_name = load_filename(context, names[lt], entry+lt, lfn_buf2);

			if(compare(entry_name, entry+lt, pivot_name, entry) < 0) {
				lt++;
			} else {
				if(lt!=gt)
					swap(entry+lt, names+lt, entry+gt, names+gt);
				gt--;
			}
		}
		
		// put the pivot in place
		if(lt > 0)
			swap(entry, names, entry+lt-1, names+lt-1);

		pivot = lt-1;
		int c1 = pivot, c2 = count-pivot-1;

		// recurse the smaller range
		if(c1 > c2) {
			quicksort(context, entry+pivot+1, names+pivot+1, c2);
			count = c1;
		} else {
			quicksort(context, entry, names, c1);
			entry += pivot+1;
			names += pivot+1;
			count = c2;
		}
	}
}

static void sort_entries(struct dir_context *context, unsigned short **filenames)
{
	quicksort(context, entries, filenames, entries_total);
}

static unsigned short *wstrdup(unsigned short *src, int chars)
{
	unsigned short *rv = malloc(chars*2);
	if(rv)
		memcpy(rv, src, chars*2);
	return rv;
}

// SDK malloc apparently operates using an MMU? Anyway, we have to monitor the free space
// explicitly instead of depending on malloc() to return NULL - it will usually crash before this.

// measured in 128-byte pages
// Threshold picked by trial & error.
#define MEM_THRESHOLD 400
int pmalloc_get_unused_pages();

int hook_f_readnextdir(FATFS* fs, DIR *dj, DIRINFO *dirinfo, FS_NAME *pathbuf)
{
	if(dj->iter.cindex == 0xfffe) // past-last
		return 130;

	// cache the sorted iterator table for the last read directory
	if(dj->id.obj.sclust != sclust_loaded) {
		// scan & sort
		DIR mydj;
		memcpy(&mydj, dj, sizeof(DIR));
		f_opendir(fs, &mydj);
		
		unsigned short *filenames[MAX_ENTRIES];
		int oom = 0;

		// list all pre-scan DIR values
		entries_total = 0;
		int rv;
		for(;;) {
			FS_NAME my_pathbuf = {0};
			my_pathbuf.lfn = lfn_buf1;

			wdt_clr();
			// read the next entry, including LFN (unless we hit OOM early)
			memcpy(&entries[entries_total], &mydj.iter, sizeof(DIR_ITER));
			rv = f_readnextdir_trampoline(fs, &mydj, dirinfo, oom ? 0 : &my_pathbuf);
			if(rv >= 130) 
				break;

			if(oom) {
				filenames[entries_total] = 0;
			} else {
				// decode LFN/SFN path into utf-16
				int chars = filename_decode(my_pathbuf.lfn, my_pathbuf.lfn_cnt, dirinfo->fname);

				// store in a compact buffer
				filenames[entries_total] = wstrdup(my_pathbuf.lfn, chars+1);
				if(!filenames[entries_total])
					// Note that this implementation of malloc will usually crash inside vmalloc
					// before returning NULL. This path will not be reached.
					oom = 1;

				if(pmalloc_get_unused_pages() < MEM_THRESHOLD)
					// Safeguard against an OOM scenario.
					oom = 1;
			}

			++entries_total;
			if(entries_total == MAX_ENTRIES)
				break;
		}

//		if(oom)
//			binlog('o',0,0);

		if(entries_total < MAX_ENTRIES) {
			struct dir_context context = { fs, &dj->id };
			sort_entries(&context, filenames);
		}

		int i;
		for(i=0;i<entries_total;i++) 
			if(filenames[i])
				free(filenames[i]);

		sclust_loaded = dj->id.obj.sclust;
	}

	// fallback to unsorted for >= MAX_ENTRIES
	if(entries_total == MAX_ENTRIES) 
		return f_readnextdir_trampoline(fs, dj, dirinfo, pathbuf);

	unsigned short nth = dj->iter.cindex+1;
	if(nth >= entries_total) {
		dj->iter.cindex = 0xfffe;
		return 130;
	}

	// run the function for the nth value
	memcpy(&dj->iter, &entries[nth], sizeof(DIR_ITER));
	int rv = f_readnextdir_trampoline(fs, dj, dirinfo, pathbuf);

	// return the manipulated cindex
	dj->iter.cindex = nth;
	return rv;
}

// overwrite f_readnextdir, hence the trampoline above
int f_readnextdir(FATFS* fs, DIR *dj, DIRINFO *dirinfo, FS_NAME *pathbuf);
PATCH_GOTO(f_readnextdir, hook_f_readnextdir);

// a missing ftell function for file_decoder
int file_ftell(void *ptr)
{
	return fpos((*(FILE***)0x2734)[63]);
}
PATCH_U32(0x1e11cd0, file_ftell);
