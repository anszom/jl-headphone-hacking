/* 
 * Various debugging functions
 */
#include "asm/cpu.h"
#include "asm/br36.h"
#include "debug.h"
#include <string.h>

#include "patcher.h"
#include "asm/pwm_led.h"

void softdelay(int ms)
{
	// Rough approximation, matching the higher clock. The headphones boot with a 4x lower one.
	while(ms-->0)
		for(volatile int i=0;i<8000;i++);
}

void flash(int n)
{
	while(n-->0) {
		pwm_led_mode_set(PWM_LED0_ON);
		softdelay(150);
		pwm_led_mode_set(PWM_LED1_ON);
		softdelay(50);
	}
	pwm_led_mode_set(PWM_LED_ALL_OFF);
}

// Reboots into the bootloader mode
// FIXME: in some cases this fails to do its job, instead the device boots in some kind of a
// broken USB mode. It's unknown what causes this to fail or resolve itself.
void reboot2uboot()
{
	*(volatile unsigned int*)0x28800 = 0xed627375;   // "usb" tag word 0
	*(volatile unsigned int*)0x28804 = 0xef678163;   //           word 1
	*(volatile unsigned char*)0x1a38a0 |= 0x10;      // chip_reset
	for(;;);
}

// reconstructed from labels in the prebuilt sdk code
struct exc_frame {
	u32 r[16]; // r0..r15
	u32 reti;
	u32 rete;
	u32 retx;
	u32 rets;
	u32 psr;
	u32 icfg;
	u32 usp; // user stack pointer ?
	u32 ssp;
};

#ifdef DEVMODE
// hooked SDK function, forwards exception data into binlog for postmortem debugging
void exception_analyze_hook(struct exc_frame *frame)
{
	// clear ETM_CON in case it is still running
	*((volatile unsigned int*)0x1be1c0)=0;
	binlog('X', frame, 96); 	// exception frame
	binlog('U', (void*)frame->usp, 128);	// user stack
	unsigned int etm[] = {
		*((volatile unsigned int*)0x1be1c4), // ETM_PC0..4
		*((volatile unsigned int*)0x1be1c8),
		*((volatile unsigned int*)0x1be1cc),
		*((volatile unsigned int*)0x1be1d0),
		*((volatile unsigned int*)0x1be200), // EMU_CON
		*((volatile unsigned int*)0x1be204), // EMU_MSG
	};
	// instruction trace
	binlog('T', etm, sizeof(etm));

	reboot2uboot();
}
// this is exception_analyze, the flash copy
PATCH_GOTO(0x1e0bd9c, exception_analyze_hook);
#endif

void  __attribute__((naked)) reboot2uboot_trampoline()
{
	asm("r0 = reboot2uboot\ngoto r0");
}

void debug_init()
{
// Our patch_image.py doesn't handle patching code-in-RAM. We patch p33_soft_reboot at runtime
// to reboot into uboot instead. This should run only in debug builds, so that the headphones
// simply reboot normally in case of a fault.
#ifdef DEVMODE
	// only 14 bytes of space there!
	memcpy((volatile void*)&p33_soft_reset, reboot2uboot_trampoline, 8);
#endif
}

#ifdef BINLOG
// In-memory binary log. It's retained on reboot->uboot, so it can be analyzed from the PC.
unsigned char binlog_data[1024];
int binlog_off;
void binlog(char id, const void *data, int size)
{
	if(binlog_off >= sizeof(binlog_data)-3)
		return;

	local_irq_disable();
	if(binlog_off >= sizeof(binlog_data)-3) {
		local_irq_enable();
		return;
	}

	if(binlog_off+3+size >= sizeof(binlog_data))
		size = sizeof(binlog_data)-binlog_off-3;

	if(size==0 || data==0) {
		binlog_data[binlog_off++] = id;
	} else {
		binlog_data[binlog_off++] = id|0x80;
		binlog_data[binlog_off++] = size&0xff;
		binlog_data[binlog_off++] = (size>>8)&0xff;
		memcpy(binlog_data+binlog_off, data, size);
		binlog_off += size;
	}
	local_irq_enable();
}
#else
void binlog(char id, const void *data, int size)
{}
#endif
