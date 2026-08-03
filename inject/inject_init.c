/* Minimal runtime init for injected code built with gen_symld.py --data-addr.
 *
 * The injected .data runs in RAM (VMA) but its initializer is stored in flash
 * after the code (LMA); .bss is RAM the firmware never zeroes. Call inject_init()
 * ONCE from your injected entry point, before touching any writable global:
 * it copies .data from its flash image into RAM and zeroes .bss.
 *
 * The linker symbols come from gen_symld.py's --data-addr layout. Declared as
 * bytes so `&sym` is the address; only their addresses are used, never values.
 *
 * The destination pointer is volatile on purpose: without it the compiler
 * recognizes these loops and lowers them to memset/memcpy calls, but those live
 * in the maskrom ~30 MB away — out of the +/-4 MB branch reach of injected code
 * (the firmware only reaches ROM via the +2^25 mirror). volatile keeps the init
 * self-contained, depending on nothing outside the payload.
 */
extern unsigned char __idata_load;    /* flash: .data initializer image (LMA) */
extern unsigned char __idata_start;   /* RAM:   .data start (VMA)             */
extern unsigned char __idata_end;     /* RAM:   .data end                     */
extern unsigned char __ibss_start;    /* RAM:   .bss start                    */
extern unsigned char __ibss_end;      /* RAM:   .bss end                      */

void inject_init(void)
{
    const unsigned char *src = &__idata_load;
    volatile unsigned char *dst;

    for (dst = &__idata_start; dst < &__idata_end; )
        *dst++ = *src++;
    for (dst = &__ibss_start; dst < &__ibss_end; )
        *dst++ = 0;
}
