#define PATCH_MARKER_TYPE_CALL 0
#define PATCH_MARKER_TYPE_GOTO 1
#define PATCH_MARKER_TYPE_U32 2
#define PATCH_MARKER_TYPE_U8 3
struct patch_marker { int type; void *arg1, *arg2; };
#define PM_CONCAT1(a,b) a ## b
#define PM_CONCAT(a,b) PM_CONCAT1(a,b)
#define PATCH_MARKER(t, a, b) PATCH_MARKER1(t, a, b, PM_CONCAT(__pm_, __COUNTER__)) 
#define PATCH_MARKER1(t, a, b, label) static const struct patch_marker label \
		__attribute__((section(".patchmeta"), used)) = { t, (void*)(a), (void*)(b) }

#define PATCH_CALL(source, target) PATCH_MARKER(PATCH_MARKER_TYPE_CALL, source, target)
#define PATCH_GOTO(source, target) PATCH_MARKER(PATCH_MARKER_TYPE_GOTO, source, target)
#define PATCH_U32(source, target) PATCH_MARKER(PATCH_MARKER_TYPE_U32, source, target)
#define PATCH_U8(source, target) PATCH_MARKER(PATCH_MARKER_TYPE_U8, source, target)
