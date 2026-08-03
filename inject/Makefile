TC=$(HOME)/Downloads/jl/jieli-linux-toolchains-20250324.1/pi32v2
SDK=$(HOME)/Dev/jl/JL7006
DEFINES=-DBINLOG -DDEVMODE
CFLAGS= \
	-I$(SDK)/include_lib \
	-I$(SDK)/include_lib/driver/cpu/br36 \
	-I$(SDK)/include_lib/system \
	-I$(SDK)/include_lib/system/generic \
	-I$(SDK)/include_lib/media/media_new \
	-I$(TC)/include \
	-I$(SDK) \
       -I$(SDK)/include_lib/system/os/FreeRTOS/pi32v2/ \
       -DCONFIG_FREE_RTOS_ENABLE -DVFS_ENABLE=1 \
       -DBYTE_ORDER=1234 -DLITTLE_ENDIAN=1234 -DBIG_ENDIAN=4321 \
       -Itremor \
       $(DEFINES)

OBJS=inject_init.o debug.o main.o trampoline.o fs.o ogg.o \
	tremor/vorbisfile.o \
	tremor/bitwise.o tremor/codebook.o tremor/dsp.o tremor/floor0.o tremor/floor1.o tremor/floor_lookup.o tremor/framing.o tremor/info.o tremor/mapping0.o tremor/mdct.o tremor/res012.o

inject.elf: inject.ld.out $(OBJS)
	$(TC)/bin/ld -T $^ -o $@ $(TC)/lib/libcompiler-rt.a

inject.ld.out: inject.ld app.ld
	$(TC)/bin/cc -E -P -x c $< -o $@ $(DEFINES)

clean:
	rm -f $(OBJS) inject.elf inject.ld.out

%.o: %.c
	${TC}/bin/clang -c $< -o $@  -Os -target pi32v2 -mcpu=r3  $(CFLAGS)

%.o: %.S
	${TC}/bin/clang -c $< -o $@  -Os -target pi32v2 -mcpu=r3  $(CFLAGS)
