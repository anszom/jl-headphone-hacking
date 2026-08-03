/*
 * Ogg-Vorbis decoder.
 *
 * This requires a series of hooks. Ideally, we would add another entry to the decoder table, but this would require
 * us to copy the whole table elsewhere (to grow it). Instead, I've picked an arbitrary decoder that I don't use (AAC),
 * and replaced its definition.
 *
 * Also requires patching:
 * 1. default format mask
 * 2. file extension list (we replace MP1 with OGG) 
 */

#include "asm/cpu.h"

#include "media/audio_base.h"
#include "media/audio_decoder.h"
#include "ivorbisfile.h"
#include "debug.h"
#include "patcher.h"

typedef struct ogg_decoder {
	struct audio_decoder *adec;
	OggVorbis_File vf;
	int start_offset;
	char samples[1024];
	short fill, off;
} ogg_decoder;

static size_t ogg_fread(void *buf, size_t one, size_t nbytes, void *ctx)
{
	struct audio_decoder *ad = ctx;
	return ad->input->ops.file.fread(ad, buf, nbytes);
}

static int ogg_fseek(void *ctx, int64_t pos, int whence)
{
	struct audio_decoder *ad = ctx;
	if(!ad->input->ops.file.ftell)
		return -1;

	// underlying fseek doesn't support SEEK_END
	if(whence == SEEK_END) {
		whence = SEEK_SET;
		pos += ad->input->ops.file.flen(ad);
	}

	return ad->input->ops.file.fseek(ad, pos, 0);
}

static int ogg_fclose(void *ctx)
{
	return 0;
}

static long ogg_ftell(void *ctx)
{
	struct audio_decoder *ad = ctx;
	return ad->input->ops.file.ftell(ad);
}

static const ov_callbacks io_callbacks = {
	ogg_fread,
	ogg_fseek,
	ogg_fclose,
	ogg_ftell
};

void vorbis_dsp_set_cache_area(unsigned char *start, unsigned int size);

ogg_decoder *ogg_open(struct audio_decoder *adec)
{
	struct ogg_decoder *ogg = zalloc(sizeof(ogg_decoder));
	if(!ogg) 
		return ogg;
	ogg->adec = adec;
	ogg->adec->input->ops.file.fseek(ogg->adec, 0, 0);
	ov_open_callbacks((void *)adec, &ogg->vf, 0, 0, io_callbacks);

	return ogg;
}

int ogg_get_fmt(ogg_decoder *ogg, struct audio_fmt *fmt)
{
	if(ogg->vf.ready_state<2)
		return 2; // not opened = mismatch

	vorbis_info *info = ov_info(&ogg->vf, -1);
	fmt->channel = info->channels;
	fmt->frame_len = info->channels*2;
	fmt->sample_rate = info->rate;
	fmt->total_time = 1000;
	return 0;
}

int ogg_set_output_channel(ogg_decoder *ogg, enum audio_channel nch)
{
	// FIXME this would need to be implemented, but we only use 2ch output with 2ch ogg files,
	// so it works with the defaults.
	return 0;
}

int ogg_get_breakpoint(ogg_decoder *ogg, struct audio_dec_breakpoint *bp)
{
	bp->len = 1; // just in case the caller special-cases zero
	bp->fptr = ov_pcm_tell(&ogg->vf);
	return 0;
}

int ogg_set_breakpoint(ogg_decoder *ogg, struct audio_dec_breakpoint *bp)
{
	// SDK implementations simply stash the pointer. I'm not sure how this would be supposed to work
	// Copy the file pointer out.
	ogg->start_offset = bp->fptr;
	return 0;
}

int ogg_start(ogg_decoder *ogg)
{
	if(ogg->start_offset != 0) 
		ov_pcm_seek(&ogg->vf, ogg->start_offset);
	return 0;
}

int ogg_run(ogg_decoder *ogg, u8 *premain)
{
	int rv = 0;
	for(;;) {
		if(ogg->fill == 0) {
			int bs;
			int nr = ov_read(&ogg->vf, ogg->samples, sizeof(ogg->samples), &bs);
			if(nr == 0) {
				rv = AUDIO_DEC_EVENT_END;
				break;
			}

			if(nr < 0) {
				continue;
			}
			ogg->fill = nr;
			ogg->off = 0;
		}

		int n = audio_decoder_put_output_buff(ogg->adec, ogg->samples + ogg->off, ogg->fill, 0);
		if(n <= 0)
			break;

		if(n < ogg->fill) {
			ogg->off += n;
			ogg->fill -= n;
			break;
		} else {
			ogg->fill = ogg->off = 0;
		}
	}

	return rv;
}

int ogg_close(ogg_decoder *ogg)
{
	ogg->adec->input->ops.file.fseek(ogg->adec, 0, 0);
	ov_clear(&ogg->vf);
	free(ogg);
	return 0;
}

void *_ogg_malloc(size_t sz)
{
	return malloc(sz);
}

void *_ogg_realloc(void *old, size_t newsize, size_t oldsize)
{
	void *out = newsize ? malloc(newsize) : 0;
	if(old && out) 
		memcpy(out, old, newsize<oldsize?newsize:oldsize);
	if(old)
		free(old);
	return out;	
}

void *memchr(const void*_a, int chr, size_t size)
{
	const unsigned char *a = _a;
	while(size-->0) {
		if(*a == chr)
			return (void*)a;
		a++;
	}
	return 0;
}

PATCH_U32(0x1e11cbc, 0x1a06); // format mask
PATCH_U8(0x1e12ae6, 'O'); // extension list
PATCH_U8(0x1e12ae7, 'G');
PATCH_U8(0x1e12ae8, 'G');

PATCH_U32(0x1e39268, ogg_open);
PATCH_U32(0x1e3926c, ogg_start);
PATCH_U32(0x1e39270, ogg_get_fmt);
PATCH_U32(0x1e39274, ogg_set_output_channel);
PATCH_U32(0x1e39284, ogg_get_breakpoint);
PATCH_U32(0x1e39288, ogg_set_breakpoint);
PATCH_U32(0x1e39294, ogg_run);
PATCH_U32(0x1e3929c, ogg_close);

