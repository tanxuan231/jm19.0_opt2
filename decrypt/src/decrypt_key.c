#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>

#define MAX_KEYBUF_SIZE 1024*1024*20
#define MAX_264BUF_SIZE 1024*1024*50
#define MAX_KEY_UNIT_SIZE 512  // 最大的密钥单元大小

#define BOFFSET_PRIFIX_LEN 2
#define DATALEN_PRIFIX_LEN 2
#define BOFFSET_FLAG_LEN 4
#define BITOFFSET_LEN 3
#define DATALEN_FLAG_LEN 4

int prefix[4] = {0, 1, 2, 3};

typedef struct
{
	uint8_t* start;
	uint8_t* p;
	uint8_t* end;
	int bits_left;
} bs_t;

static inline int bs_eof(bs_t* b) { if (b->p >= b->end) { return 1; } else { return 0; } }

static inline bs_t* bs_init(bs_t* b, uint8_t* buf, size_t size)
{
    b->start = buf;
    b->p = buf;
    b->end = buf + size;
    b->bits_left = 8;
    return b;
}

static inline bs_t* bs_new(uint8_t* buf, size_t size)
{
    bs_t* b = (bs_t*)malloc(sizeof(bs_t));
    bs_init(b, buf, size);
    return b;
}

static inline void bs_free(bs_t* b)
{
    free(b);
}

static inline void bs_skip_u1(bs_t* b)
{    
    b->bits_left--;
    if (b->bits_left == 0) { b->p ++; b->bits_left = 8; }
}

static inline void bs_skip_u(bs_t* b, int n)
{
    int i;
    for ( i = 0; i < n; i++ ) 
    {
        bs_skip_u1( b );
    }
}

static inline uint32_t bs_read_u1(bs_t* b)
{
    uint32_t r = 0;
    
    b->bits_left--;

    if (! bs_eof(b))
    {
        r = ((*(b->p)) >> b->bits_left) & 0x01;
    }

    if (b->bits_left == 0) { b->p ++; b->bits_left = 8; }

    return r;
}

/*读buffer的前n位，结果以十进制u32 return*/
static inline uint32_t bs_read_u(bs_t* b, int n)
{
    uint32_t r = 0;
    int i;
    for (i = 0; i < n; i++)
    {
        r |= ( bs_read_u1(b) << ( n - i - 1 ) );
    }
    return r;
}

static void decrypt_byteoffset(bs_t* b, int* byteoffset)
{	
	int boffset_prifix_len = 0;
	*byteoffset = 0;
	boffset_prifix_len = bs_read_u(b, BOFFSET_PRIFIX_LEN);

	if(boffset_prifix_len == 0)	// read 2 bits and +4
	{
		*byteoffset = bs_read_u(b, 2) + 4;
	}
	else if(boffset_prifix_len == 1) // read 3 bits and +8
	{
		*byteoffset = bs_read_u(b, 3) + 8;
	}
	else if(boffset_prifix_len == 2) // read 4 bits and +16
	{
		*byteoffset = bs_read_u(b, 4) + 16;
	}
	else	// read 4bits flag
	{
		int flag = bs_read_u(b, BOFFSET_FLAG_LEN);
		*byteoffset = bs_read_u(b, flag);
	}
}

static void decrypt_datalen(bs_t* b, int* datalen)
{
	int datalen_prifix_len = 0;
	*datalen = 0;
	datalen_prifix_len = bs_read_u(b, BOFFSET_PRIFIX_LEN);

	if(datalen_prifix_len == 0)	// read 1 bits and +2
	{
		*datalen = bs_read_u1(b) + 2;
	}
	else if(datalen_prifix_len == 1) // read 3 bits and +8
	{
		*datalen = bs_read_u(b, 3) + 8;
	}
	else if(datalen_prifix_len == 2) // read 4 bits and +16
	{
		*datalen = bs_read_u(b, 4) + 16;
	}
	else	// read 4bits flag
	{
		int flag = bs_read_u(b, DATALEN_FLAG_LEN);
		*datalen = bs_read_u(b, flag);
	}	
}

static void decrypt_data(FILE* h264file, bs_t*b, int byteoffset, int bitoffset, int datalen)
{
	int bit_sum 		= bitoffset + datalen;
	int read_byte 	= 0;
	int first_byte_mask = 0;	
	int last_byte_mask = 0;
	char buf_264[MAX_KEY_UNIT_SIZE] = {0};
	int data;
	int i;
	
	//counting the bytes should be read to deal with
	read_byte = bit_sum/8;
	if(bit_sum%8)
		read_byte++;
	
	fseek(h264file, byteoffset, SEEK_CUR);
	int cur_pos = ftell(h264file);
	int rd_cnt = fread(buf_264, sizeof(char), read_byte + 1, h264file);
	//printf("read cnt: %d\n",rd_cnt);

	if(bit_sum > 8)	//over than one byte
	{
		first_byte_mask = bitoffset;	// 第一个字节从前往后的位数
		last_byte_mask  = read_byte*8 - bit_sum;	// 最后一个字节从后往前的位数

		/*** write_back_to_264buf ***/
		//deal with the first byte
		data = bs_read_u(b, 8 - first_byte_mask);
		buf_264[0] |= data;

		//deal with the other bytes		
		for(i = 1;i < read_byte -1; ++i)
			buf_264[i] |= bs_read_u(b, 8);

		//deal with the last byte
		buf_264[read_byte - 1] |= (bs_read_u(b, 8 - last_byte_mask) << (last_byte_mask));
	}
	else if(bit_sum == 8)	//only one byte
	{		
		first_byte_mask = bitoffset;

		/*** write_back_to_264buf ***/
		data = bs_read_u(b, datalen);
		buf_264[0] |= data;
	}
	else  //litter then a byte
	{
		first_byte_mask = bitoffset;
		last_byte_mask  = read_byte*8 - bit_sum;

		/*** write_back_to_264buf ***/
		data = bs_read_u(b, datalen);
		buf_264[0] |= (data << (8 - bitoffset - datalen));
	}

	fseek(h264file, cur_pos, SEEK_SET);
	fwrite(buf_264, sizeof(char), rd_cnt, h264file);
	fseek(h264file, cur_pos, SEEK_SET);
}

static void decrypt_one_unit(FILE* h264file, bs_t* b)
{
#if 0
	FILE* log = fopen("de_key_unit_log", "w+");
	if(!log)
	{
		printf("open de_key_unit_log error!\n");
		exit(1);
	}
	char s[255];
#endif	
	int byteoffset = 0;
	int bitoffset = 0;
	int datalen = 0;

	while(b->p < b->end)
	{
		//printf("p: 0x%x, end: 0x%x, len: %d\n",b->p, b->end, b->end - b->p);
		decrypt_byteoffset(b, &byteoffset);
		bitoffset = bs_read_u(b, BITOFFSET_LEN);
		decrypt_datalen(b, &datalen);
		decrypt_data(h264file, b, byteoffset, bitoffset, datalen);

		//snprintf(s,255,"ByteOffset: %5d, BitOffset: %2d, DataLen: %4d\n",
					//byteoffset,bitoffset,datalen);
		//fwrite(s,strlen(s),1,log);
	}
}

void decryt_thread(FILE* h264file, int keyfd)
{
	int rd_cnt = 0;

	/*** malloc the buffer***/
	char* buf_key;
	buf_key = (char*)malloc(sizeof(char)*MAX_KEYBUF_SIZE);
	if(!buf_key)
	{
		printf("encryt_thread: malloc error!\n");
		exit(1);
	}		
	memset(buf_key, 0x0, MAX_KEYBUF_SIZE);

	rd_cnt = read(keyfd, buf_key, MAX_KEYBUF_SIZE);
	bs_t* b = bs_new(buf_key, rd_cnt);

	decrypt_one_unit(h264file, b);
}

int main(int argc,char **argv)
{
	char H264FilePath[255]={0x00};
	char KeyFilePath[255]={0x00};
	char DeleteKeyFile[255]="rm ";
	if(strcmp(argv[1],"-s")==0 && strcmp(argv[3],"-k")==0)
	{
		memcpy(H264FilePath,argv[2],strlen(argv[2]));
		memcpy(KeyFilePath,argv[4],strlen(argv[4]));
	}
	else
	{
		printf("usage: ./a.out -s [H264FilePath] -k [KeyFilePath] \n");
		return 0;
	}
	
	H264FilePath[strlen(argv[2])]=0x00;
	KeyFilePath[strlen(argv[4])]=0x00;

	if(!strlen(H264FilePath) || !strlen(KeyFilePath))
		return 0;
	
	//int h264fd;
	FILE* h264file = NULL;
	int keyfd;
	keyfd	 		= open(KeyFilePath,O_RDONLY);
	h264file 	= fopen(H264FilePath, "r+");
	
	if(h264file==NULL)
	{
		printf("open h264file error!!\n");
		exit(-1);
	}
	else
	{
		printf("open %s success!\n",H264FilePath);
	}

	if(keyfd == -1)
	{
		printf("open KeyFile error!!\n");
		exit(-1);
	}
	else
	{
		printf("open %s success!\n",KeyFilePath);
	}

	decryt_thread(h264file, keyfd);
	fsync(fileno(h264file));
	
	close(keyfd);
	fclose(h264file);	
	
	return 1;
}


