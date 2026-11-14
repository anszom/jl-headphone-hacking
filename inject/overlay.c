#include "overlay.h"

void overlay_load(void)
{
	const unsigned char *src = &__overlay_load;
	volatile unsigned char *dst;
	for (dst = &__overlay_start; dst < &__overlay_end; )
		*dst++ = *src++;
}
