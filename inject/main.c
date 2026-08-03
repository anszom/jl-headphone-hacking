/* 
 * Main hook file. It handles:
 * - launching early init code from app_task_init
 * - modifying music-mode key handling (switch by folder)
 * - modifying backwards-folder-seek behavior
 */

#include "system/event.h"
#include "system/fs/fs.h"
#include "asm/br36.h"
#include "asm/pwm_led.h"
#include "device/key_driver.h"
#include "media/audio_base.h"
#include "media/audio_decoder.h"
#include "media/file_decoder.h"
#include "key_events.h"

#include "patcher.h"
#include "debug.h"

void inject_init(void);
void app_task_init(void);

void hook_app_task_init()
{
	inject_init();
	debug_init();
	return app_task_init();
}

void app_task_handler();
PATCH_CALL(((char*)app_task_handler)+2, hook_app_task_init);

// the original function doesn't have the `decoded_key` argument, but r2 is unused
// in the prologue so we abuse it as an extra parameter
void music_event_handler(void *app, struct sys_event *event, int decoded_key);

// in play mode, we swap next/prev to match vol+/-
const unsigned char playing_key_table[][KEY_EVENT_MAX] = {
	{ KEY_MUSIC_PP, KEY_POWEROFF,   KEY_POWEROFF_HOLD, KEY_NULL, KEY_MODE_SWITCH, KEY_MUSIC_CHANGE_REPEAT },
	{ KEY_VOL_UP,   KEY_MUSIC_NEXT, KEY_NULL,          KEY_NULL, KEY_NULL, KEY_NULL },
	{ KEY_VOL_DOWN, KEY_MUSIC_PREV, KEY_NULL,          KEY_NULL, KEY_NULL, KEY_NULL },
};

// in pause mode, next/prev runs by whole folders
const unsigned char paused_key_table[][KEY_EVENT_MAX] = {
	{ KEY_MUSIC_PP, KEY_POWEROFF,                KEY_POWEROFF_HOLD, KEY_NULL, KEY_MODE_SWITCH, KEY_MUSIC_CHANGE_REPEAT },
	{ KEY_VOL_UP,   KEY_MUSIC_PLAYE_NEXT_FOLDER, KEY_NULL,          KEY_NULL, KEY_NULL, KEY_NULL },
	{ KEY_VOL_DOWN, KEY_MUSIC_PLAYE_PREV_FOLDER, KEY_NULL,          KEY_NULL, KEY_NULL, KEY_NULL },
};

#define file_dec (*((struct file_decoder**)0x2734))

void hook_music_event_handler(void *app, struct sys_event *event)
{
	int decoded_key = 0;
	// remap keys depending on play/pause state
	if(event->type == SYS_KEY_EVENT && event->arg == (void*)DEVICE_EVENT_FROM_KEY) {
		if(file_dec && file_dec->status == FILE_DEC_STATUS_PLAY) {
			decoded_key = playing_key_table[event->u.key.value][event->u.key.event];
		} else {
			decoded_key = paused_key_table[event->u.key.value][event->u.key.event];
		}
	}

	music_event_handler(app, event, decoded_key);
}
// music app definition
PATCH_U32(0x1e10a48, hook_music_event_handler);
PATCH_U32(0x1e08a90, 0x1627); // in music_event_handler, strategically placed r7=r2;nop

FILE *file_manager_select(void *dev, struct vfscan *fsn, int op, int num, void *cb);

FILE *hook_fm_select(void *dev, struct vfscan *fsn, int op, int num, void *cb)
{
	FILE *rv = file_manager_select(dev, fsn, op, num, cb);
	if(op != FSEL_PREV_FOLDER_FILE || rv == 0)
		return rv;
	
	if(!fsn->priv)
		return rv;

	// this replicates MUSIC_PLAYER_PLAY_FOLDER_PREV_FIRST_FILE_EN

	// fget_folder is not compiled-in. Bypass vfs layer and extract data from vfat driver directly.
	// We *could* go via fat_ioctl but why bother
	short fileStart = ((short*)fsn->priv)[267] + 1;

	fclose(rv);
	return file_manager_select(dev, fsn, FSEL_BY_NUMBER, fileStart, cb);
}

PATCH_CALL(0x1e08f9e, hook_fm_select); // file_manager -> previous folder hook
