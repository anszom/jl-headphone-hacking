# JL7006 headphone hacking

This repo contains my custom firmware patch for cheap "bone-conduction" headphones. Published in the odd case that someone may find it useful.

The headphones are designed for swimming, so apart from bluetooth mode (which would be useless underwater), they have a builtin SD card and
can play stored music. The headphones work well, in general, but the software is annoying in various aspects. Once I've found that the
software can be dumped & modified, I've started tinkering, reaching for more & more ambitious goals as I went. The journey is sparsely documented below.

## Warning

The headphones are glued shut. If you decide to make any changes to the firmware, it's only a matter of time until you run into a hard lockup,
that can only be resolved by power-cycling - like shorting the battery. I have been able to pry them open non-destructively, but it's not easy.

If you mess up, you're on your own.

## 0. Dump the firmware

This required three pieces:
- jl-uboot-tool (submodule)
- br36 loaded binary (found somewhere, included in jl-uboot-tool now)
- uboot dongle (can be bought on aliexpress or bit-banged by any microcontroller)

## 1. Unpack & disassemble

- jl-misctools (submodule)
- Ghidra + [ghidra-jieli](https://github.com/quarkslab/ghidra-jieli).

A [vendor SDK](https://github.com/honokahqh/JL7006) was immensely helpful for code analysis. My headphones appear to be compiled from
a slightly different revision, but most code & structs still match.

An LLM spat out a bunch of analysis scripts, you can find them in tools/. The most useful part is a symbol matcher, which allows me
to get a partially-symbolized elf from the binary firmware dump. The symbols are assigned by comparing the symbolized output from the
SDK with the firmware dump and matching instruction sequences.

## 2. Fix the annoying button swap

The headphones only have three buttons
- power (or mode switch)
- volume + (previous track)
- volume - (next track)

I have no idea why they decided to swap the direction between volume & tracks. Fixing this was relatively straightforward - the key-function
mapping is stored in a global table, so patching two bytes was all that was needed for this.

I've used some more AI-slop scripts to repack the firmware & load it on the headphones. There are no signature checks, so nothing to worry about.

## 3. Folder selection

The three buttons don't allow for easy navigation. I wanted a simple "next folder" / "previous folder" switch. 

For button assignments, I've decided to switch button assignments depending on the play/pause status. When paused, a long +/- press would
switch to the next/previous folder (instead of next/previous file).

It turns out that navigating by folders was already implemented in the SDK code, but going backwards was buggy. A workaround was even available, but
guarded with a default-off #ifdef (`MUSIC_PLAYER_PLAY_FOLDER_PREV_FIRST_FILE_EN`), so it didn't make it into my headphones' firmware. It was easy to
replicate in my custom code though (`hook_fm_select`).

But how do I get the custom code to run together with the original firmware? Some more python scripts fell out of an LLM's bottom, and I've cobbled
together a binary patching workflow:

- gen_symld.py produces a bunch of PROVIDE() directives to declare the firmware's symbols
- my code is built with the vendor's [toolchain](https://pkgman.jieliapp.com/s/linux-toolchain)
- a custom linker script places my code at the end of the original .text section, and carves out some RAM space from the area originally assigned for the heap
- special PATCH_xxx() preprocessor directives output data into a `.patchmeta` section, allowing the C code to select points in the original firmware that it will hook into
- patch_image.py combines the original firmware with the patch elf file, and applies the patches from `.patchmeta`
- finally a repacker puts the updated code into the full firmware image

Build, flash, test, repeat.

## 4. Detour: debugging

The headphones don't run when connected to USB, they don't have an UART output, only two LEDs (white & green in the same spot). For debugging my code,
I've resorted to an in-memory log buffer. When the "uboot dongle" is connected, the headphones reboot to bootloader directly, without clearing RAM,
so the buffer's contents can be recovered (see jlraw.py). I've also hooked the exception handler to dump the crash frame into the buffer and reboot
to the bootloader. It isn't bulletproof, but works most of the time.

## 5. Folder sorting

This is a weakness of most cheap music players: they read the directories in storage order, or - roughly speaking - in the order the files were
created, not sorted by name. The resulting playback order depends on the software that was used to copy files to the drive. Not ideal.

So, I've hooked directory iteration functions to sort files during enumeration - see fs.c.

To be honest, at this point I've reached the "just for show" territory - folder sorting can be easily fixed while copying files, no need to force
the device to do it.

## 6. Vorbis playback

Since everything was going well, I've decided to reach for the most ambitious goal - adding support for a new music format. Originally, the player
supports MP3, AAC, FLAC (I think), WAV, and some others. Notably, no Vorbis. A reasonable person would just transcode the music, but we know that is not
the point here :)

The music playback infrastructure is surprisingly cleanly designed. There are separate format handlers, each described with a set of function pointers
not unlike a C++ vtable. Interfacing the `tremor` fixed-point decoder to the firmware's infrastructure needed roughly 200 lines of code. The most challenging
part was RAM consumption:

- tremor "lowmem" branch was absolutely necessary so that the decoder could work with only a few tens of KB RAM available
- various uses of `alloca` had to be replaced with heap allocations, because of the limited stack space

Afterwards, it "just worked"... but not very well. The headphones' battery would drain after an hour of playback, or ~4x faster than with MP3. Of course,
measuring power consumption in sealed headphones is problematic, so I've checked a few things blindly. One weakness of the tremor implementation was
the use of flash-stored lookup tables. The JieLi chip has very small caches, so there were a lot of d-cache misses during playback. Moving the most
frequently used data to RAM reduced this dramatically, and extended the battery lifetime at least 2x (I've stopped the test after 2 hours).

## Target device

My headphones are branded "Occamo SwimBeat" headphones. This appears to be a brand used exclusively by the Polish importer, but similar-looking devices can
be found in various stores online. The headphones run on the JL7006 chip.

My unit has firmware that I can only identify by its hash. I can't publish the original firmware for obvious reasons.
```
> dd if=dump1 bs=$[0x860b0]c count=1 | md5sum
1f4a33cc4d16856c364581ab813fb7c4 -
```

## Commands

Prepare: 
```
mkdir work; export TOOLCHAIN=~/Downloads/jl/jieli-linux-toolchains-20250324.1/pi32v2/bin/
```

Dump: 
```
python3 ./jl-uboot-tool/jluboottool.py  'read 0 0x100000 work/dump.bin'
# Save the original dump.bin somewhere safe
```

Unpack: 
```
python3 ./jl-misctools/firmware/fwunpack_newfw.py work/dump.bin --dirname work/unpacked
cp -r work/unpacked work/repacked
# modify fwpack.yaml to grow app.bin: app_area_head.size, app.bin.size cfg_tool.bin.offset VM.offset, VM.size, PRCT.size
# truncate work/repacked/partitions/VM.bin to fit the new size
```

app.img -> app.elf:
```
python3 tools/rebuild_elf.py  --bin work/unpacked/files/app.bin  --out work/app.elf --rom-lst ../JL7006/cpu/br36/tools/rom.lst --stubs ../JL7006/cpu/br36/maskrom_stubs.ld
```

Reconstruct symbols: 
```
python3 tools/jlgraph.py  --sdk ../JL7006/cpu/br36/tools/sdk.elf --app work/app.elf --objdump $TOOLCHAIN/objdump --workdir work
```

app.rebuilt.elf, with symbols: 
```
python3 tools/rebuild_elf.py  --bin work/unpacked/files/app.bin  --out work/app.rebuilt.elf --rom-lst ../JL7006/cpu/br36/tools/rom.lst --stubs ../JL7006/cpu/br36/maskrom_stubs.ld --map work/graph_map.tsv
```

Symbols -> linkerscript: 
```
python3 tools/gen_symld.py --elf work/app.rebuilt.elf -o inject/app.ld
```

Build inject image:
```
make -C inject
```

Patch app.bin:
```
python3 ./tools/patch_image.py  inject/inject.elf --data 0x1e494ca --bin work/unpacked/files/app.bin  --out work/repacked/files/app.bin
```

Repack:
```
python3 ./jl-misctools/firmware/fwpack_newfw.py work/repacked work/dump-mod.bin
```

Write:
```
python3 ./jl-uboot-tool/jlubootool.py 'write 0 work/dump-mod.bin' reset
```

## Useful links:

- JieLi STUFF: https://kagaimiq.github.io/jielie/ - a treasure trove of information
- ghidra-jieli: https://github.com/quarkslab/ghidra-jieli
- vendor SDK: https://github.com/honokahqh/JL7006
- post-build tools: https://pkgman.jieliapp.com/s/linux-postbuild
