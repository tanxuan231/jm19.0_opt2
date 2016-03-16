#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "global.h"
#include "encrypt_key.h"
/************************************************************************************/
#define MAX_264BUF_SIZE 1024*1024*110	// 120MB
#define MAX_KEYBUF_SIZE 1024*1024*50	// 50MB

char hash_high[9] = 
{
	0x0,
	0x80, // 1000 0000
	0xc0,	// 1100 0000	
	0xe0,	// 1110 0000	
	0xf0,	// 1111 0000	
	0xf8,	// 1111 1000	
	0xfc,	// 1111 1100	
	0xfe,	// 1111 1110	
	0xff	// 1111 1111	
};
char hash_low[9] 	= 
{
	0x00,	// 0000 0000
	0x01,	// 0000 0001
	0x03,	// 0000 0011
	0x07,	// 0000 0111
	0x0f,	// 0000 1111
	0x1f, // 0001 1111
	0x3f,	// 0011 1111
	0x7f,	// 0111 1111
	0xff	// 1111 1111
};

char hash_key_high[9] =
{
	0xff, // 1111 1111
	0x7f, // 0111 1111
	0x3f, // 0011 1111
	0x1f, // 0001 1111
	0x0f, // 0000 1111
	0x07, // 0000 0111
	0x03, // 0000 0011
	0x01, // 0000 0001
	0x0,	// 0000 0000
};
//key unit format
/*
*	byte offset
*	 prifix		|byte offset len  | storage code
*		0x00 		|	4~7							|	0~3  2bits
* 	0x01 		| 8~15						|	0~7	 3bits
* 	0x10 		| 16~31						| 0~15 4bits
*		0x11		| others					|
*		when flag = 0x11,should use 4 bits to decide the length(could reach 0~15bits and the length could reach 0~32767) of byte offset 
*		0x11 + flag(4bits) + byte_offset
*	bit offset: 3bits
*	data length
*	 prifix		|data len  	| storage code
*		0x00 		|	2~3				|	0~3  2bits
* 	0x01 		| 8~15			|	0~7	 3bits
* 	0x10 		| 16~31			| 0~15 4bits
*		0x11		| others		|
*		when flag = 0x11,should use 4 bits to decide the length(could reach 0~15bits and the length could reach 0~32767) of byte offset 
*		0x11 + flag(4bits) + data_len
* data: data_len bits
*/
int prefix[4] = {0, 1, 2, 3};
//#define BOFFSET_FLAG_LEN 2
#define BOFFSET_FLAG_LEN 4
#define BOFFSET_PRIFIX_LEN 2
#define BITOFFSET_LEN 3
#define DATALEN_PRIFIX_LEN 2

unsigned int count_bits(unsigned int n)
{
	int i = 0;
	while(n)
	{
		n >>= 1;
		i++;
	}

	return i;
}

static inline void* en_malloc(size_t size)
{
	void* tmp = malloc(size);
	if(!tmp)
	{
		printf("en_malloc error!\n");
		exit(1);
	}
}

static void KU_copy(KeyUnit* dest, KeyUnit* src)
{
	dest->bit_offset = src->bit_offset;
	dest->byte_offset = src->byte_offset;
	dest->key_data_len = src->key_data_len;
}

static void write_byteoffset_to_keybuffer(bs_t* b, unsigned int byteoffset)
{
	unsigned int storage = 0;
	int flag = 0;
	int id = 0;
	
	if(byteoffset >= 4 && byteoffset <= 7)
	{
		id = 0;
		storage = byteoffset - 4; // 0~3 2bits
		bs_write_u(b, BOFFSET_PRIFIX_LEN, prefix[id]);
		bs_write_u(b, 2, storage);
	}
	else if(byteoffset >= 8 && byteoffset <=15)
	{
		id = 1;
		storage = byteoffset - 8;	//	0~7 3bits
		bs_write_u(b, BOFFSET_PRIFIX_LEN, prefix[id]);
		bs_write_u(b, 3, storage);		
	}
	else if(byteoffset >= 16 && byteoffset <= 31)
	{
		id = 2;
		storage = byteoffset - 16;	//	0~15 4bitss
		bs_write_u(b, BOFFSET_PRIFIX_LEN, prefix[id]);
		bs_write_u(b, 4, storage);		
	}
	else
	{
		id = 3;
		flag = count_bits(byteoffset);
		bs_write_u(b, BOFFSET_PRIFIX_LEN, prefix[id]);
		bs_write_u(b, BOFFSET_FLAG_LEN, flag);
		bs_write_u(b, flag, byteoffset);
	}	
}

static void write_bitoffset_to_keybuffer(bs_t* b, int bitoffset)
{
	bs_write_u(b, BITOFFSET_LEN, bitoffset);
}

static void write_datalen_to_keybuffer(bs_t* b, int datalen)
{
	unsigned int storage = 0;
	int flag = 0;
	int id = 0;

	if(datalen >= 2 && datalen <= 3)
	{
		id = 0;
		storage = datalen - 2; // 0~1 1bits
		bs_write_u(b, DATALEN_PRIFIX_LEN, prefix[id]);
		bs_write_u1(b, storage);		
	}
	else if(datalen >= 8 && datalen <= 15)
	{
		id = 1;
		storage = datalen - 8;	// 0~7 3bits
		bs_write_u(b, DATALEN_PRIFIX_LEN, prefix[id]);
		bs_write_u(b, 3, storage);
	}
	else if(datalen >= 16 && datalen <= 31)
	{
		id = 2;
		storage = datalen - 16;	// 0~15 4bits
		bs_write_u(b, DATALEN_PRIFIX_LEN, prefix[id]);
		bs_write_u(b, 4, storage);		
	}
	else
	{
		id = 3;
		flag = count_bits(datalen);
		bs_write_u(b, DATALEN_PRIFIX_LEN, prefix[id]);
		bs_write_u(b, BOFFSET_FLAG_LEN, flag);
		bs_write_u(b, flag, datalen);		
	}
}

// 加密一个密钥单元
// buf_264_start is the start of dealing with one unit int h264 bit stream
// b point to the buf_key
static void encryt_one_unit(bs_t* b, char* buf_264, int buf_264_start, KeyUnit* KUBuf, int KUBuf_idx)
{
	int i;

	int byteoffset 	= KUBuf[KUBuf_idx].byte_offset;
	int bitoffset 	= KUBuf[KUBuf_idx].bit_offset;
	int datalen			= KUBuf[KUBuf_idx].key_data_len;
	int bit_sum 		= bitoffset + datalen;
	int read_byte 	= 0;

	//counting the bytes should be read to deal with
	read_byte = bit_sum/8;
	if(bit_sum%8)
		read_byte++;

	#if 0
	printf("read_byte: %d\n",read_byte);

	printf("print the data before change:\n");	
	for(i=buf_264_start; i<buf_264_start + read_byte; ++i)
		printf("0x%x ",buf_264[i]);
	printf("\n");
	#endif

	write_byteoffset_to_keybuffer(b, byteoffset);
	write_bitoffset_to_keybuffer(b, bitoffset);
	write_datalen_to_keybuffer(b, datalen);

	int first_byte_mask = 0;	
	int last_byte_mask = 0;

	if(bit_sum > 8)	//over than one byte
	{
		first_byte_mask = bitoffset;	// 第一个字节从前往后的位数
		last_byte_mask  = read_byte*8 - bit_sum;	// 最后一个字节从后往前的位数

		/*** write_keydata_to_keybuf ***/
		bs_write_u(b, 8 - first_byte_mask, buf_264[buf_264_start]);
		for(i = buf_264_start + 1; i < buf_264_start + read_byte -1; ++i)
			bs_write_u8(b, buf_264[i]);
		bs_write_c(b, 8 - last_byte_mask, buf_264[buf_264_start + read_byte - 1]);

		/*** write_0_to_264buf ***/
		//deal with the first byte
		buf_264[buf_264_start] &= hash_high[first_byte_mask];

		//deal with the other bytes		
		for(i = buf_264_start + 1;i < buf_264_start + read_byte -1; ++i)
			buf_264[i] &= 0x0;

		//deal with the last byte
		buf_264[buf_264_start + read_byte - 1] &= hash_low[last_byte_mask];
	}
	else if(bit_sum == 8)	//only one byte
	{		
		first_byte_mask = bitoffset;

		/*** write_keydata_to_keybuf ***/
		bs_write_u(b, 8 - first_byte_mask, buf_264[buf_264_start]);
		/*** write_0_to_264buf ***/
		buf_264[buf_264_start] &= hash_high[first_byte_mask];
	}
	else  //litter then a byte
	{
		first_byte_mask = bitoffset;
		last_byte_mask  = read_byte*8 - bit_sum;

		/*** write_keydata_to_keybuf ***/
		bs_write_an(b, bitoffset, datalen, buf_264[buf_264_start]);
		/*** write_0_to_264buf ***/
		char tmp = hash_high[first_byte_mask] ^ hash_low[last_byte_mask];
		buf_264[buf_264_start] &= tmp;
	}

	#if 0
	printf("print the data after change:\n");
	for(i=buf_264_start; i<buf_264_start + read_byte; ++i)
		printf("0x%x ",buf_264[i]);
	printf("\n");
	#endif
}

void encryt_thread(ThreadUnitPar* thread_unit_par)
{	
	int i = 0, j = 0;		
	int rd_cnt;

	/*** malloc the buffer***/
	char* buf_264;
	buf_264 = (char*)malloc(sizeof(char)*MAX_264BUF_SIZE);
	if(!buf_264)
	{
		printf("encryt_thread: malloc error!\n");
		exit(1);
	}
	memset(buf_264, 0x0, MAX_264BUF_SIZE);
	
	char* buf_key;
	buf_key = (char*)malloc(sizeof(char)*MAX_KEYBUF_SIZE);
	if(!buf_key)
	{
		printf("encryt_thread: malloc error!\n");
		exit(1);
	}		
	memset(buf_key, 0x0, MAX_KEYBUF_SIZE);
	
	KeyUnit* KUBuf;
	KUBuf = (KeyUnit*)malloc(sizeof(KeyUnit)*thread_unit_par->buffer_len);
	if(!KUBuf)
	{
		printf("encryt_thread: malloc error!\n");
		exit(1);
	}	

	j = 0;
	for(i = thread_unit_par->buffer_start; i < thread_unit_par->buffer_len; i++)	// should locked g_pKeyUnitBuffer
	{
		KU_copy(&KUBuf[j],&g_pKeyUnitBuffer[i]);
		j ++;
	}

	//FILE* keyfile = p_Dec->p_KeyFile;
	int key_fd = p_Dec->KeyFileFd;
	int h264_fd = p_Dec->BitStreamFile;//open("bus_cavlc_Copy.264",O_RDWR);	
	lseek(h264_fd, thread_unit_par->cur_absolute_offset, SEEK_SET);	// should locked h264_fd
	rd_cnt = read(h264_fd, buf_264, MAX_264BUF_SIZE);	// should locked h264_fd

	bs_t* b = bs_new(buf_key, MAX_KEYBUF_SIZE);


	/*** encryt every key unit***/
	int start = 0;
	//KUBuf[0].byte_offset = 0;	
	for(i = thread_unit_par->buffer_start; i < thread_unit_par->buffer_len; i++)
	{
		if(i > thread_unit_par->buffer_start)
			start += KUBuf[i].byte_offset;
		if(start > rd_cnt)
		{
			printf("buf is too litter!\n");
		}
		encryt_one_unit(b, buf_264, start, KUBuf, i);
	}


	/*** write back to file ***/
	int wr_cnt;
	lseek(h264_fd, thread_unit_par->cur_absolute_offset, SEEK_SET);
	wr_cnt = write(h264_fd, buf_264, rd_cnt);	// should locked h264_fd
	if(wr_cnt == -1)
	{
		printf("write to 264 bs error!\n");
	}
	else if(wr_cnt != rd_cnt)
	{
		printf("write to 264 bs file litter than the cnt: %d < %d\n",wr_cnt, rd_cnt);
	}
	fsync(h264_fd);
	
	wr_cnt = write(key_fd, buf_key, b->p - b->start + 1);
	if(wr_cnt == -1)
	{
		printf("write to 264 bs error!\n");
	}
	fsync(key_fd);
	
	/*** free the buffer ***/
	bs_free(b);
	free(buf_264);
	free(buf_key);
	free(KUBuf);	
}
/************************************************************************************/

