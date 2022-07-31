# Hash_value

# 项目介绍
Find a key with hash value “sdu_cst_20220610” under a message composed of your name followed by your student ID. For example, “San Zhan 202000460001”.
# 运行方法
直接运行即可
# 实现方法
为了实现逆向的过程，最需要实现的就是AES解密的逆向，此处不能简单的使用_mm_aesenc_si128（）函数，因为AES使用的是等价解密。因此我们需要利用AVX中关于aes的现存指令来实现。

![image](https://user-images.githubusercontent.com/75195549/182007601-b2c9c1b3-e323-4c87-a17e-ecccfe7d0390.png)



设计逆向函数，计算出固定的消息与hash值的key出来。




# 函数解析

#### define MixColumns(A) A = _mm_aesdeclast_si128(A, _mm_setzero_si128()); A = _mm_aesenc_si128(A, _mm_setzero_si128())
由于AES的指令中没有直接的列混合的函数，这里把两个aes的加密指令放在一起

#### define psubq(A, B) A = _mm_sub_epi64(A, B)
模加逆运算

#### define inv_mixcol(A) A = _mm_aesimc_si128(A)
AES列混淆

#### define subbytes_and_shiftrow(A) aesenc(A, _mm_setzero_si128());inv_mixcol(A)
通过将解密最后一轮和加密结合做到实现先字节替换再行移位

#### AES Inversity


![image](https://user-images.githubusercontent.com/75195549/182007716-751bafe8-7dc5-479a-b1bb-768f43a26336.png)



#### MEOW_SHUFFLE的逆过程

![image](https://user-images.githubusercontent.com/75195549/182007724-50180abe-83ae-4ff9-a9e1-9c8bf3690277.png)



#### MeowHash的逆函数


将MeowHash（）颠倒过来，需要注意的是由于本题目的长度小于32bytes，所以没有写入那些full block的处理过程，而是直接进行填充等操作。因此使用本函数的时候消息不能超过32bytes

```
void MeowHash_inv(void* Hash, void* M, meow_umm Len, void* Key)
{
    meow_u128 xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7; // NOTE(casey): xmm0-xmm7 are the hash accumulation lanes
    meow_u128 xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15;

    meow_u8* rcx = (meow_u8*)Hash;
    movdqu(xmm0, rcx + 0x00);//此处接受了最后的hash值
    movdqu(xmm1, rcx + 0x10);//后面就属于越界访存，但是我们并不关心具体是什么
    movdqu(xmm2, rcx + 0x20);
    movdqu(xmm3, rcx + 0x30);
    movdqu(xmm4, rcx + 0x40);
    movdqu(xmm5, rcx + 0x50);
    movdqu(xmm6, rcx + 0x60);
    movdqu(xmm7, rcx + 0x70);

    psubq(xmm0, xmm4);//最后squeeze的逆过程
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

    //下面复制的头文件中关于处理不满的32byte数据的处理方法
    //由于本题要求的消息比较短，因此我们不再处理其他的部分
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
```





# 结果展示

![image](https://user-images.githubusercontent.com/75195549/182007634-8e4f47cb-2b57-49f8-a9df-d60ff2313316.png)




