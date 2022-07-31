#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "Hash_value.h"
using namespace std;



#define subbytes_and_shiftrow(A) aesenc(A, _mm_setzero_si128());inv_mixcol(A)

#define aesdec_inv(A, B) \
pxor(A, B);  \
MixColumns(A); \
subbytes_and_shiftrow(A)


#define MEOW_SHUFFLE_INV(r1, r2, r3, r4, r5, r6) \
pxor(r2, r3);\
psubq(r5, r6); \
aesdec_inv(r4, r2); \
pxor(r4, r6); \
psubq(r2, r5); \
aesdec_inv(r1, r4)
#define movdqu(A, B)  A = _mm_loadu_si128((__m128i *)(B))
#define psubq(A, B) A = _mm_sub_epi64(A, B) 
#define pxor(A, B)    A = _mm_xor_si128(A, B)
#define aesenc(A, B)  A = _mm_aesenc_si128(A, B)
#define pxor_clear(A, B)    A = _mm_setzero_si128();
#define aesdec(A, B)  A = _mm_aesdec_si128(A, B)
#define inv_mixcol(A) A = _mm_aesimc_si128(A) 
#define movdqu(A, B)  A = _mm_loadu_si128((__m128i *)(B))
#define palignr(A, B, i) A = _mm_alignr_epi8(A, B, i)
#define movq(A, B) A = _mm_set_epi64x(0, B);
#define pand(A, B)    A = _mm_and_si128(A, B)
#define pshufb(A, B)  A = _mm_shuffle_epi8(A, B)
#define INSTRUCTION_REORDER_BARRIER _ReadWriteBarrier()
#define movdqu_mem(A, B)  _mm_storeu_si128((__m128i *)(A), B)


#define MixColumns(A) A = _mm_aesdeclast_si128(A, _mm_setzero_si128()); A = _mm_aesenc_si128(A, _mm_setzero_si128())




#define MEOW_MIX_REG_INV(r1, r2, r3, r4, r5,  i1, i2, i3, i4) \
pxor(r4, i4);\
psubq(r5, i3); \
INSTRUCTION_REORDER_BARRIER; \
aesdec_inv(r2, r4);\
pxor(r2, i2);  \
psubq(r3, i1);   \
INSTRUCTION_REORDER_BARRIER; \
aesdec_inv(r1, r2);

void MeowHash_inv(void* Hash, void* M, meow_umm Len, void* Key)
{
    meow_u128 xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7; // NOTE(casey): xmm0-xmm7 are the hash accumulation lanes
    meow_u128 xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15;

    meow_u8* rcx = (meow_u8*)Hash;
    movdqu(xmm0, rcx + 0x00);
    movdqu(xmm1, rcx + 0x10);
    movdqu(xmm2, rcx + 0x20);
    movdqu(xmm3, rcx + 0x30);
    movdqu(xmm4, rcx + 0x40);
    movdqu(xmm5, rcx + 0x50);
    movdqu(xmm6, rcx + 0x60);
    movdqu(xmm7, rcx + 0x70);

    psubq(xmm0, xmm4);
    pxor(xmm0, xmm1);
    pxor(xmm4, xmm5);
    psubq(xmm0, xmm2);
    psubq(xmm1, xmm3);
    psubq(xmm4, xmm6);
    psubq(xmm5, xmm7);

    MEOW_SHUFFLE_INV(xmm3, xmm4, xmm5, xmm7, xmm0, xmm1);//此为12轮finalization的逆过程
    MEOW_SHUFFLE_INV(xmm2, xmm3, xmm4, xmm6, xmm7, xmm0);
    MEOW_SHUFFLE_INV(xmm1, xmm2, xmm3, xmm5, xmm6, xmm7);
    MEOW_SHUFFLE_INV(xmm0, xmm1, xmm2, xmm4, xmm5, xmm6);
    MEOW_SHUFFLE_INV(xmm7, xmm0, xmm1, xmm3, xmm4, xmm5);
    MEOW_SHUFFLE_INV(xmm6, xmm7, xmm0, xmm2, xmm3, xmm4);
    MEOW_SHUFFLE_INV(xmm5, xmm6, xmm7, xmm1, xmm2, xmm3);
    MEOW_SHUFFLE_INV(xmm4, xmm5, xmm6, xmm0, xmm1, xmm2);
    MEOW_SHUFFLE_INV(xmm3, xmm4, xmm5, xmm7, xmm0, xmm1);
    MEOW_SHUFFLE_INV(xmm2, xmm3, xmm4, xmm6, xmm7, xmm0);
    MEOW_SHUFFLE_INV(xmm1, xmm2, xmm3, xmm5, xmm6, xmm7);
    MEOW_SHUFFLE_INV(xmm0, xmm1, xmm2, xmm4, xmm5, xmm6);

    pxor_clear(xmm9, xmm9);
    pxor_clear(xmm11, xmm11);

    meow_u8* Last = (meow_u8*)M + (Len & ~0xf);
    int unsigned Len8 = (Len & 0xf);
    if (Len8)
    {
        movdqu(xmm8, &MeowMaskLen[0x10 - Len8]);

        meow_u8* LastOk = (meow_u8*)((((meow_umm)(((meow_u8*)M) + Len - 1)) | (MEOW_PAGESIZE - 1)) - 16);
        int Align = (Last > LastOk) ? ((int)(meow_umm)Last) & 0xf : 0;
        movdqu(xmm10, &MeowShiftAdjust[Align]);
        movdqu(xmm9, Last - Align);
        pshufb(xmm9, xmm10);

        pand(xmm9, xmm8);
    }


    if (Len & 0x10)
    {
        xmm11 = xmm9;
        movdqu(xmm9, Last - 0x10);
    }

    xmm8 = xmm9;
    xmm10 = xmm9;
    palignr(xmm8, xmm11, 15);
    palignr(xmm10, xmm11, 1);


    pxor_clear(xmm12, xmm12);
    pxor_clear(xmm13, xmm13);
    pxor_clear(xmm14, xmm14);
    movq(xmm15, Len);
    palignr(xmm12, xmm15, 15);
    palignr(xmm14, xmm15, 1);


    MEOW_MIX_REG_INV(xmm1, xmm5, xmm7, xmm2, xmm3, xmm12, xmm13, xmm14, xmm15);

    MEOW_MIX_REG_INV(xmm0, xmm4, xmm6, xmm1, xmm2, xmm8, xmm9, xmm10, xmm11);

    meow_u8* rax = (meow_u8*)Key;
    movdqu_mem(rax + 0x00, xmm0);
    movdqu_mem(rax + 0x10, xmm1);
    movdqu_mem(rax + 0x20, xmm2);
    movdqu_mem(rax + 0x30, xmm3);
    movdqu_mem(rax + 0x40, xmm4);
    movdqu_mem(rax + 0x50, xmm5);
    movdqu_mem(rax + 0x60, xmm6);
    movdqu_mem(rax + 0x70, xmm7);

}

void Printkey(meow_u8* key)
{
    meow_u128* t = (meow_u128*)key;
    for (int i = 0; i < 8; i++)
    {
        printf("    %08X%08X%08X%08X",
            MeowU32From(t[i], 3),
            MeowU32From(t[i], 2),
            MeowU32From(t[i], 1),
            MeowU32From(t[i], 0));
    }
}


int main()
{
    char hash[] = "sdu_cst_20220610";
    char message[] = "Liujinyuan 202000460082";
    cout << "Hash value is" << hash << endl;
    cout << "what hash value is need?:" << message << endl;
    meow_umm len = strlen(message);
    meow_u8 key[128] = { 0 };
    MeowHash_inv(hash, message, len, key);
    cout << "key inversity" << endl;
    Printkey(key);
    meow_u128 Hash = MeowHash(key, len, message);
    meow_u128* a = &Hash;
    cout << endl;
    cout << "Hash:" << endl;
    for (int i = 0; i < 16; i++)
    {
        cout << ((char*)a)[i];
    }
    cout << endl;
    system("pause");
    return 0;

}
