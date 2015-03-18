#include "stdio.h"
#include "memory.h"
#include "stdlib.h"
#include <string.h>
#define PLAIN_FILE_OPEN_ERROR -1
#define CIPHER_FILE_OPEN_ERROR -3
#define OK 1
const static char IP_Table[64] =
    {
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
    };

    const static char IP_1_Table[64] =
    {
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25
    };

    static const char E_Table[48] =
    {
        32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
         8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
    };

    const static char P_Table[32] =
    {
        16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
        2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25
    };

    const static char PC_1[56] =
    {
        57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
    };
    const static char PC_2[48] =
    {
        14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
        23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    };

    const static char S[8][4][16] = {
        // S1
        14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
         0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
         4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
        15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
        // S2
        15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
         3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
         0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
        13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
        // S3
        10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
        13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
        13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
         1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
        // S4
         7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
        13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
        10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
         3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
        // S5
         2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
        14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
         4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
        11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,
        // S6
        12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
        10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
         9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
         4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,
        // S7
         4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
        13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
         1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
         6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
        // S8
        13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
         1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
         7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
         2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
    };

    const static char MOVE_TIMES[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

char x1[9];
char x2[9];
char plainBlock1[17];
char plainBlock2[17];
char keyBlock[17]="3132333435363738";
char cipherBlock[17];
bool bKey[64];
bool subKeys[17][48];
void Transform(bool *Out, bool *In, const char *Table, int len)
    {
        int i;
        for(i=0; i<len; ++i)
            Out[i] = In[ Table[i]-1 ];
    }
void Bit4ToChar(bool bit[4],char *ch)
{
    int s=0;
    if(bit[0]==1)
        s=s+8;
    if(bit[1]==1)
        s=s+4;
    if(bit[2]==1)
        s=s+2;
    if(bit[3]==1)
        s=s+1;
    if(s<10)
        *ch='0'+s;
    if(s>=10)
        *ch='A'+s-10;
}
void CharToBit4(char *ch,bool bit[4])
{
    int s;
    if(*ch>='A')
        s=(*ch)-'A'+10;
    else
        s=(*ch)-'0';
    if(s>=8)
        {bit[0]=1;s=s-8;}
    else bit[0]=0;
    if(s>=4)
        {bit[1]=1;s=s-4;}
    else bit[1]=0;
    if(s>=2)
        {bit[2]=1;s=s-2;}
    else bit[2]=0;
    if(s==1)
        bit[3]=1;
    else bit[3]=0;
}
//将二进制串转换为HEX串
int Bit64ToHex16(bool bit[64],char hex[16])
{
    memset(hex,0,sizeof(int)*16);
    int cnt;
    for(cnt=0;cnt<16;cnt++)
    {
        Bit4ToChar(bit+cnt*4,hex+cnt);
    }
    return 0;
}
//将HEX串转换为二进制串
int Hex16ToBit64(char hex[16],bool bit[64])
{
    int cnt;
    for(cnt=0;cnt<16;cnt++)
    {
        CharToBit4(hex+cnt,bit+4*cnt);
    }
    return 0;
}
//循环左移
int DES_ROL(bool data[56], int time)
{
	bool temp[28];
	memcpy(temp,data,28);
	memcpy(data,data+time,28-time);
	memcpy(data+28-time,temp,time);
	memcpy(temp,data+28,28);
	memcpy(data+28,data+28+time,28-time);
	memcpy(data+56-time,temp,time);
	return 0;
}
//生成子密钥
int DES_MakeSubKeys(bool key[64],bool subKeys[16][48])
{
	bool temp[56];
	int cnt;
	Transform(temp,key,PC_1,56);//PC1置换
	for(cnt = 0; cnt < 16; cnt++)
	{//16轮跌代，产生16个子密钥
		DES_ROL(temp,MOVE_TIMES[cnt]);//循环左移
		Transform(subKeys[cnt],temp,PC_2,48);//PC2置换，产生子密钥
	}
	return 0;
}

void Char8ToHex16(char ch8[8],char hex16[16])
{
	int i;
	for(i=0;i<8;i++)
	{
		hex16[2*i]=ch8[i]/16+48;		
		hex16[2*i+1]=ch8[i]%16+48;
		if(hex16[2*i]>=58)
			hex16[2*i]+=7;
		if(hex16[2*i+1]>=58)
			hex16[2*i+1]+=7;
	}
}
void Hex16ToChar8(char hex16[16],char ch8[8])
{
	int i;
	for(i=0;i<8;i++)
	{
		if(hex16[2*i]>='A')
			hex16[2*i]-=55;
		else
			hex16[2*i]-=48;
		if(hex16[2*i+1]>='A')
			hex16[2*i+1]-=55;
		else
			hex16[2*i+1]-=48;
		ch8[i]=hex16[2*i]*16+hex16[2*i+1];
	}
	
}


//异或
int DES_XOR(bool *out,bool *R, bool *L ,int count)
{
	int cnt;
	for(cnt = 0; cnt < count; cnt++)
	{
		out[cnt]=R[cnt] ^ L[cnt];
	}
	return 0;
}

//S盒置换
int DES_SBOX(bool data[48],bool r[32])
{
	int cnt;
	int line,row,output;
	int cur1,cur2;
	for(cnt = 0; cnt < 8; cnt++)
	{
		cur1 = cnt*6;
		cur2 = cnt*4;

		//计算在S盒中的行与列
		line = (data[cur1]*2) + data[cur1+5];
		row = (data[cur1+1]*8) + (data[cur1+2]*4)
			+ (data[cur1+3]*2) + data[cur1+4];
		output = S[cnt][line][row];

		//化为2进制
		r[cur2] = (output&0X08)>>3;
		r[cur2+1] = (output&0X04)>>2;
		r[cur2+2] = (output&0X02)>>1;
		r[cur2+3] = output&0x01;
	}
	return 0;
}

//交换
int DES_Swap(bool left[32], bool right[32])
{
	bool temp[32];
	memcpy(temp,left,32);
	memcpy(left,right,32);
	memcpy(right,temp,32);
	return 0;
}

//加密单个分组
int DES_EncryptBlock(char plainBlock[16], bool subKeys[16][48],char cipherBlock[16])
{
	bool m[64];
	bool plainBits[64];
	bool copyRight[48];
	bool L[17][32];
	bool R[17][32];
	bool F[17][32];
	bool B[48];
	bool C[32];
	int cnt;
	Hex16ToBit64(plainBlock,plainBits);
	//初始置换（IP置换）
	Transform(m,plainBits,IP_Table,64);
	memcpy(&L[0][0],&m[0],32);
	memcpy(&R[0][0],&m[32],32);
	//16轮迭代
	for(cnt = 1; cnt <= 16; cnt++)
	{
		memcpy(L[cnt],R[cnt-1],32);
		//将右半部分进行扩展置换，从32位扩展到48位
		Transform(copyRight,R[cnt-1],E_Table,48);
		//将右半部分与子密钥进行异或操作
		DES_XOR(B,copyRight,subKeys[cnt-1],48);
		//异或结果进入S盒，输出32位结果
		DES_SBOX(B,C);
		//P置换
		Transform(F[cnt],C,P_Table,32);
		//将明文左半部分与右半部分进行异或
		DES_XOR(R[cnt],L[cnt-1],F[cnt],32);
	}
	memcpy(&m[0],&R[16][0],32);
	memcpy(&m[32],&L[16][0],32);
	//逆初始置换（IP^1置换）
	Transform(plainBits,m,IP_1_Table,64);
	Bit64ToHex16(plainBits,cipherBlock);
	return 0;
}

//解密单个分组
int DES_DecryptBlock(char cipherBlock[16], bool subKeys[16][48],char plainBlock[16])
{
	bool m[64];
	bool cipherBits[64];
	bool copyRight[48];
	bool L[17][32];
	bool R[17][32];
	bool F[17][32];
	bool B[48];
	bool C[32];
	int cnt;
	Hex16ToBit64(cipherBlock,cipherBits);
	//初始置换（IP置换）
	Transform(m,cipherBits,IP_Table,64);
	memcpy(&L[0][0],&m[0],32);
	memcpy(&R[0][0],&m[32],32);
	//16轮迭代
	for(cnt = 1; cnt <= 16; cnt++)
	{
		memcpy(L[cnt],R[cnt-1],32);
		//将右半部分进行扩展置换，从32位扩展到48位
		Transform(copyRight,R[cnt-1],E_Table,48);
		//将右半部分与子密钥进行异或操作
		DES_XOR(B,copyRight,subKeys[16-cnt],48);
		//异或结果进入S盒，输出32位结果
		DES_SBOX(B,C);
		//P置换
		Transform(F[cnt],C,P_Table,32);
		//将明文左半部分与右半部分进行异或
		DES_XOR(R[cnt],L[cnt-1],F[cnt],32);
	}
	memcpy(&m[0],&R[16][0],32);
	memcpy(&m[32],&L[16][0],32);
	//逆初始置换（IP^1置换）
	Transform(cipherBits,m,IP_1_Table,64);
	Bit64ToHex16(cipherBits,plainBlock);
	return 0;
}

//加密文件
int DES_Encrypt()
{
    int cnt;
	FILE *plain,*cipher;
	int count;
	if((plain = fopen("1.txt","rb")) == NULL)
	{
		return PLAIN_FILE_OPEN_ERROR;
	}
	if((cipher = fopen("2.txt","wb")) == NULL)
	{
		return CIPHER_FILE_OPEN_ERROR;
	}
	while(!feof(plain))
	{
		//每次读16个字节，并返回成功读取的字节数
		if((count = fread(x1,sizeof(char),8,plain)) == 8)
		{
			Char8ToHex16(x1,plainBlock1);
			DES_EncryptBlock(plainBlock1,subKeys,cipherBlock);
			fwrite(cipherBlock,sizeof(char),16,cipher);
		}
	}	
	Char8ToHex16(x1,plainBlock1);
	count*=2;
	if(count){
		//填充
		memset(plainBlock1 + count,'0',15 - count);
		
		//最后一个字符保存包括最后一个字符在内的所填充的字符数量
		if(16-count<10)		plainBlock1[15]=64-count;
		else				plainBlock1[15]=71-count;
		
		DES_EncryptBlock(plainBlock1,subKeys,cipherBlock);
		fwrite(cipherBlock,sizeof(char),16,cipher);
	}
	fclose(plain);
	fclose(cipher);
	return OK;
}

//解密文件
int DES_Decrypt()
{
	FILE *plain, *cipher;
	int count,times = 0;
	long fileLen;
	int i;
	if((cipher = fopen("2.txt","rb")) == NULL)
	{
		return CIPHER_FILE_OPEN_ERROR;
	}
	if((plain = fopen("3.txt","wb")) == NULL)
	{
		return PLAIN_FILE_OPEN_ERROR;
	}
	//取文件长度
	fseek(cipher,0,SEEK_END);	//将文件指针置尾
	fileLen = ftell(cipher);	//取文件指针当前位置
	rewind(cipher);				//将文件指针重指向文件头
	while(1)
	{
		//密文的字节数一定是16的整数倍
		fread(cipherBlock,sizeof(char),16,cipher);
		DES_DecryptBlock(cipherBlock,subKeys,plainBlock2);
		times += 16;
		if(times < fileLen)
		{
			Hex16ToChar8(plainBlock2,x2);
			fwrite(x2,sizeof(char),8,plain);
		}
		else
		{
			break;
		}
	}
	//判断末尾是否被填充
	if(plainBlock2[15]>'9')
		count=plainBlock2[15]-55;
	else
		count=plainBlock2[15]-48;
	for(i=1;i<count;i++)
	{
		if(plainBlock2[15-i]!='0')	break;
	}
	Hex16ToChar8(plainBlock2,x2);
	if(i==count)//有填充
		fwrite(x2,sizeof(char),(16-count)/2,plain);
	else//无填充
		fwrite(x2,sizeof(char),8,plain);
	fclose(plain);
	fclose(cipher);
	return OK;
}

int main()
{
	//将密钥转换为二进制流
	Hex16ToBit64(keyBlock,bKey);
    //生成子密钥
	DES_MakeSubKeys(bKey,subKeys);
	DES_Encrypt();
	DES_Decrypt();
	return 0;
	
	//Hex16ToChar8(plainBlock1,x2);
}
