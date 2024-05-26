/*
 * NEWDES-3 by Alexander Pukall 2016
 * 
 * 9344-bit total keys
 * 7232-bit keys with 452 * 16-bit subkeys
 * 2048-bit key for RC4
 * 64-bit key for Splitmix64
 * 
 * Based on NEWDES by Robert Scott
 * 
 * 128-bit block cipher (like AES) 64 rounds
 * 
 * Uses MD2II hash function to create the 9344-bit keys
 * 
 * Code free for all, even for commercial software 
 * No restriction to use. Public Domain 
 * 
 * Compile with gcc: gcc newdes3.c -o newdes3
 * 
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define n1 1168 /* 7232-bit keys with 452 * 16-bit subkeys */
                /* 2048-bit key for RC4 */
                /* 64-bit key for Splitmix64 */

unsigned char array_rc4[256];
uint16_t numbers[65536];
int i_rc4,j_rc4;
uint64_t x;
uint64_t bb;
uint8_t xyz, count;

void rc4_init(unsigned char key[]);
uint16_t rc4_output();

int x1,x2,i;
unsigned char h2[n1];
unsigned char h1[n1*3];


static void init()
{
    
   x1 = 0;
   x2 = 0;
    for (i = 0; i < n1; i++)
        h2[i] = 0;
    for (i = 0; i < n1; i++)
        h1[i] = 0;
}

static void hashing(unsigned char t1[], size_t b6)
{
    static unsigned char s4[256] = 
    {   13, 199,  11,  67, 237, 193, 164,  77, 115, 184, 141, 222,  73,
        38, 147,  36, 150,  87,  21, 104,  12,  61, 156, 101, 111, 145,
       119,  22, 207,  35, 198,  37, 171, 167,  80,  30, 219,  28, 213,
       121,  86,  29, 214, 242,   6,   4,  89, 162, 110, 175,  19, 157,
         3,  88, 234,  94, 144, 118, 159, 239, 100,  17, 182, 173, 238,
        68,  16,  79, 132,  54, 163,  52,   9,  58,  57,  55, 229, 192,
       170, 226,  56, 231, 187, 158,  70, 224, 233, 245,  26,  47,  32,
        44, 247,   8, 251,  20, 197, 185, 109, 153, 204, 218,  93, 178,
       212, 137,  84, 174,  24, 120, 130, 149,  72, 180, 181, 208, 255,
       189, 152,  18, 143, 176,  60, 249,  27, 227, 128, 139, 243, 253,
        59, 123, 172, 108, 211,  96, 138,  10, 215,  42, 225,  40,  81,
        65,  90,  25,  98, 126, 154,  64, 124, 116, 122,   5,   1, 168,
        83, 190, 131, 191, 244, 240, 235, 177, 155, 228, 125,  66,  43,
       201, 248, 220, 129, 188, 230,  62,  75,  71,  78,  34,  31, 216,
       254, 136,  91, 114, 106,  46, 217, 196,  92, 151, 209, 133,  51,
       236,  33, 252, 127, 179,  69,   7, 183, 105, 146,  97,  39,  15,
       205, 112, 200, 166, 223,  45,  48, 246, 186,  41, 148, 140, 107,
        76,  85,  95, 194, 142,  50,  49, 134,  23, 135, 169, 221, 210,
       203,  63, 165,  82, 161, 202,  53,  14, 206, 232, 103, 102, 195,
       117, 250,  99,   0,  74, 160, 241,   2, 113};
       
    int b1,b2,b3,b4,b5;
   
	b4=0;
    while (b6) {
    
        for (; b6 && x2 < n1; b6--, x2++) {
            b5 = t1[b4++];
            h1[x2 + n1] = b5;
            h1[x2 + (n1*2)] = b5 ^ h1[x2];

            x1 = h2[x2] ^= s4[b5 ^ x1];
        }

        if (x2 == n1)
        {
            b2 = 0;
            x2 = 0;
            
            for (b3 = 0; b3 < (n1+2); b3++) {
                for (b1 = 0; b1 < (n1*3); b1++)
                    b2 = h1[b1] ^= s4[b2];
                b2 = (b2 + b3) % 256;
            }
           }
          }
        }

static void end(unsigned char h4[n1])
{
    
    unsigned char h3[n1];
    int i, n4;
    
    n4 = n1 - x2;
    for (i = 0; i < n4; i++) h3[i] = n4;
    hashing(h3, n4);
    hashing(h2, sizeof(h2));
    for (i = 0; i < n1; i++) h4[i] = h1[i];
}


    int nbround=64;

    uint16_t f[65536]; 
    uint16_t subkeys[452]; /* 16-bit subkey = 452*2 = 904 bytes */
    uint16_t b0,b1,b2,b3,b4,b5,b6,b7;

int rand_int(uint32_t nn2) {

uint16_t rnd;

rnd = rc4_output();

        return rnd % nn2;

    }


void shuffle(uint16_t *shu, uint32_t nn) {

        uint16_t ii, jj, tmmp;

    
        for (ii = nn - 1; ii > 0; ii--) {
	  

            jj = rand_int(ii + 1);

            tmmp = shu[jj];

            shu[jj] = shu[ii];

            shu[ii] = tmmp;

       }

    }

 

uint64_t next() {

	uint64_t z = (x += 0x9e3779b97f4a7c15);
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb;

	return z ^ (z >> 31);
}


void rc4_init(unsigned char key[])

{
       int tmp;
           
       for (i_rc4=0;i_rc4<256;i_rc4++)
       {
          array_rc4[i_rc4]=i_rc4;
       }
       
       
       j_rc4=0;
                 
        for (i_rc4=0;i_rc4<256;i_rc4++)
       {
         j_rc4=(j_rc4+array_rc4[i_rc4]+key[i_rc4%256])%256;
         tmp=array_rc4[i_rc4];
         array_rc4[i_rc4]=array_rc4[j_rc4];
         array_rc4[j_rc4]=tmp;
       }
 
 i_rc4=0;
 j_rc4=0;
}
       
uint16_t rc4_output()

{
       uint8_t rndbyte,decal;
       int tmp, t;
       uint16_t word;

    i_rc4=(i_rc4+1)%256;
    j_rc4=(j_rc4+array_rc4[i_rc4])%256;
    tmp=array_rc4[i_rc4];
    array_rc4[i_rc4]=array_rc4[j_rc4];
    array_rc4[j_rc4]=tmp;
    t=(array_rc4[i_rc4]+array_rc4[j_rc4])%256;

       if (xyz==0) bb=next();
       decal=56-(8*xyz);  
       rndbyte=(bb>>decal)& 0xff;
       xyz++;
       if (xyz==8) xyz=0;
 
    
    if (count==0)
     {
       rndbyte=rndbyte^array_rc4[t];
       count=1;
     }
     else
     {
       rndbyte=rndbyte+array_rc4[t];
       count=0;
     }
     
     word=rndbyte<<8;
     
    i_rc4=(i_rc4+1)%256;
    j_rc4=(j_rc4+array_rc4[i_rc4])%256;
    tmp=array_rc4[i_rc4];
    array_rc4[i_rc4]=array_rc4[j_rc4];
    array_rc4[j_rc4]=tmp;
    t=(array_rc4[i_rc4]+array_rc4[j_rc4])%256;

       if (xyz==0) bb=next();
       decal=56-(8*xyz);  
       rndbyte=(bb>>decal)& 0xff;
       xyz++;
       if (xyz==8) xyz=0;
 
    
    if (count==0)
     {
       rndbyte=rndbyte^array_rc4[t];
       count=1;
     }
     else
     {
       rndbyte=rndbyte+array_rc4[t];
       count=0;
     }
     
     word=word + rndbyte;

    return(word);


}

void init_newdes3(unsigned char h4[n1])
{

      /* the subkeys start at h4[264] */
 
      for (i=0;i<452;i++)
      {
	subkeys[i]=(h4[264+(i*2)]<<8)+(h4[264+((i*2)+1)]&0xff);
      }
      
      /* rc4 key start at h4[0] */
      
       rc4_init(h4);
     
     /* splitmix64 key start at h4[256] */
     
     
       x=0;
       for (int i=0;i<8;i++) x=(x<<8)+(h4[256+i]&0xff);
       
       xyz=0;
       count=0;
              
	
     for (int i=0;i<4096;i++) rc4_output();
         
       for (uint32_t i = 0; i < 65536; i++) {numbers[i]= i;}

        shuffle(numbers, 65536);

        for (uint32_t i = 0; i < 65536; i++) 
        {
          f[i]=numbers[i];
        }
}


void encrypt()
{
int compt;
compt=0;

for(int y=0;y<nbround;y++){ 
  
      b4 = b4 ^ f[b0 ^ subkeys[compt++]];
      b5 = b5 ^ f[b1 ^ subkeys[compt++]];
      b6 = b6 ^ f[b2 ^ subkeys[compt++]];
      b7 = b7 ^ f[b3 ^ subkeys[compt++]];

      b1 = b1 ^ f[b4 ^ subkeys[compt++]];
      b2 = b2 ^ f[b4 ^ b5];
      b3 = b3 ^ f[b6 ^ subkeys[compt++]];
      b0 = b0 ^ f[b7 ^ subkeys[compt++]];
 
   }
      b4 = b4 ^ f[b0 ^ subkeys[compt++]];
      b5 = b5 ^ f[b1 ^ subkeys[compt++]];
      b6 = b6 ^ f[b2 ^ subkeys[compt++]];
      b7 = b7 ^ f[b3 ^ subkeys[compt++]];

}

void decrypt()
{
int compt;

compt=451;

    b7 = b7 ^ f[b3 ^ subkeys[compt--]];
    b6 = b6 ^ f[b2 ^ subkeys[compt--]];
    b5 = b5 ^ f[b1 ^ subkeys[compt--]];
    b4 = b4 ^ f[b0 ^ subkeys[compt--]];
      
        
for(int y=0;y<nbround;y++){ 
  
       b0 = b0 ^ f[b7 ^ subkeys[compt--]];
       b3 = b3 ^ f[b6 ^ subkeys[compt--]];
       b2 = b2 ^ f[b4 ^ b5];
       b1 = b1 ^ f[b4 ^ subkeys[compt--]];
	
       b7 = b7 ^ f[b3 ^ subkeys[compt--]];
       b6 = b6 ^ f[b2 ^ subkeys[compt--]];
       b5 = b5 ^ f[b1 ^ subkeys[compt--]];
       b4 = b4 ^ f[b0 ^ subkeys[compt--]];
   }

}

int main()
{
      unsigned char text[33]; /* up to 256 chars for the password */
                              /* password can be hexadecimal */
                              /* strcpy = null terminated string */
      unsigned char h4[n1];

    printf("NEWDES3 by Alexander PUKALL 2016 \n 128-bit block 7232-bit subkeys 64 rounds\n");
    printf("Code can be freely use even for commercial software\n");
    printf("Based on NEWDES by Robert Scott\n\n");

    /* The key creation procedure is slow, it only needs to be done once */
    /* as long as the user does not change the key. You can encrypt and decrypt */
    /* as many blocks as you want without having to hash the key again. */
    /* init(); hashing(text,length);  end(h4); -> only once */
    /* init_newdes3(h4); -> only once too */
    
    /* EXAMPLE 1 */
    
    init();

    strcpy((char *) text,"My secret password!0123456789abZ");

    hashing(text, 32);
    end(h4); /* h4 = 9344-bit key from hash "My secret password!0123456789abZ */
    
    init_newdes3(h4);
    
    /* 0xFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE NEWDES3 block plaintext */
    
    b0=0xFEFE;b1=0xFEFE;b2=0xFEFE;b3=0xFEFE;b4=0xFEFE;b5=0xFEFE;b6=0xFEFE;b7=0xFEFE;
	
	
	printf("Key 1:%s\n",text);
    printf("Plaintext 1  :%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X\n",b0,b1,b2,b3,b4,b5,b6,b7);

    encrypt();
    
    printf("Encryption 1 :%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X\n",b0,b1,b2,b3,b4,b5,b6,b7);
       
    decrypt();
    
    printf("Decryption 1 :%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X\n\n",b0,b1,b2,b3,b4,b5,b6,b7);

    /* EXAMPLE 2 */
    
    /* 0x00000000000000000000000000000000 NEWDES3 block plaintext */
    
     b0=0x0000;b1=0x0000;b2=0x0000;b3=0x0000;b4=0x0000;b5=0x0000;b6=0x0000;b7=0x0000;
	
	printf("Key 1:%s\n",text);
    printf("Plaintext 2  :%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X\n",b0,b1,b2,b3,b4,b5,b6,b7);

    encrypt();
    
    printf("Encryption 2 :%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X\n",b0,b1,b2,b3,b4,b5,b6,b7);
       
    decrypt();
    
    printf("Decryption 2 :%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X\n\n",b0,b1,b2,b3,b4,b5,b6,b7);
	
    /* EXAMPLE 3 */
    
    /* 0x00000000000000000000000000000001 NEWDES3 block plaintext */
    
    b0=0x0000;b1=0x0000;b2=0x0000;b3=0x0000;b4=0x0000;b5=0x0000;b6=0x0000;b7=0x0001;
	
	printf("Key 1:%s\n",text);
    printf("Plaintext 3  :%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X\n",b0,b1,b2,b3,b4,b5,b6,b7);

    encrypt();
    
    printf("Encryption 3 :%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X\n",b0,b1,b2,b3,b4,b5,b6,b7);
       
    decrypt();
    
    printf("Decryption 3 :%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X%0.4X\n\n",b0,b1,b2,b3,b4,b5,b6,b7);
	
}

/*

Key 1:My secret password!0123456789abZ
Plaintext 1  :FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE
Encryption 1 :0FEA31850922D1A974EF567D9FE64DAE
Decryption 1 :FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE

Key 1:My secret password!0123456789abZ
Plaintext 2  :00000000000000000000000000000000
Encryption 2 :88FD2E43245DDE114A5826FAFB8260D9
Decryption 2 :00000000000000000000000000000000

Key 1:My secret password!0123456789abZ
Plaintext 3  :00000000000000000000000000000001
Encryption 3 :77814F85322D3E96456036838041239B
Decryption 3 :00000000000000000000000000000001

*/

