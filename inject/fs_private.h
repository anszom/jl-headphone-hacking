typedef u32 FSIZE_t;
typedef struct _FATFS FATFS;

typedef struct {
	u8      attrib;
	u32     sclust;
	FSIZE_t fsize;
} FFOBJID; // 12

typedef struct {
	u32     n_frag;//新申请到的簇连续时的计数。
	u32     n_cont;
} W_DIRINFO; // 8

// SDK struct DIR split into identity + iterator parts
typedef struct {
	FFOBJID obj;
	W_DIRINFO wdir;
} DIR_ID; // 20

typedef struct {
	u32     cd2_sect;
	u32     cd2_clust;
	u16     cd2_index;
	u16     cindex;
	u32 	clust;		        /* Current cluster */
	u32		csect;		        /* Current sector */
} DIR_ITER; // 20

typedef struct {
	DIR_ID id;
	DIR_ITER iter;
} DIR; // 40

typedef struct {
	FATFS   *fs;
	FFOBJID obj;
	W_DIRINFO wdir;
	u16     cd2_index;
	u32     cd2_sect;
	u32     cd2_clust;
	DIR     dj;
	u32     CrtTime;
	u32     WrtTime;
	u16     AccTime;
	unsigned char 	fname[16];
} DIRINFO; // 102

typedef struct _FS_NAME {
    char    tpath[128];       //路径名称buffer
    unsigned short    *lfn;             //长文件名buffer，长度LFN_MAX_SIZE×2，（前LFN_MAX_SIZE）为长文件名，（后LFN_MAX_SIZE）为长文件夹名
    unsigned short    *ldn;             //长文件名buffer，长度LFN_MAX_SIZE×2，（前LFN_MAX_SIZE）为长文件名，（后LFN_MAX_SIZE）为长文件夹名
    u16     lfn_cnt;
    u16     ldn_cnt;
} FS_NAME;


