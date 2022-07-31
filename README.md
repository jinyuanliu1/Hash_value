# Hash_value

# 项目介绍
Find a key with hash value “sdu_cst_20220610” under a message composed of your name followed by your student ID. For example, “San Zhan 202000460001”.
# 运行方法
直接运行即可
# 实现原理

为了实现逆向的过程，最重要的就是实现AES解密的逆向，此处不能简单的使用_mm_aesenc_si128（）函数，因为AES使用的是等价解密。因此我们需要利用AVX中关于aes的现存指令来实现。


![image](https://user-images.githubusercontent.com/75195549/182007818-1aa018df-af5b-4b65-980a-df11c4e0cb93.png)

AES的不对称设计十分具有迷惑性，再仔细观察上图右侧的解密过程，可以发现解密时也是白化+9轮普通轮+1轮尾轮。

这里要注意，如果直接按照加密的逆过程来考虑，那么解密应该是先解密尾轮，再解普通轮，然而上图显然不是这样。

如果不考虑轮的划分，只看分开的4种操作的话，解密的操作恰为加密操作的逆序。但若想将一系列的操作划分成不同的轮，就有很多种划分方式。上图是最常见的划分方式，其中解密轮并不是加密轮的逆运算，这一划分方式是AES的设计中第一个违反直觉的地方。

在上图的划分中，一个解密轮包括InvShiftRows，InvSubBytes，AddRoundKey，InvMixColumns操作，尾轮同样是移除InvMixColumns操作。

AES原名Rijndael，在Rijndael最初的提案中，设计者另外给出了一种“等价解密算法”（参见5.3.3 The equivalent inverse cipher structure），在等价解密中，解密轮的AddRoundKey和InvMixColumns操作顺序互换，形成了一种和加密轮相同，AddRoundKey均在最后的对称结构（InvSubBytes和InvShiftRows本身可以互换顺序）：


![image](https://user-images.githubusercontent.com/75195549/182007842-fcd33e0a-ea41-49e2-af9c-8e068310e964.png)



这一交换并非等价变换，InvMixColumns是对每一列的4个字节在GF(2^8)上乘上一个4×4矩阵，得到一个新的1×4向量，而AddRoundKey是对每个字节进行异或操作。在GF(2^8)上，异或操作即为加法运算，根据乘法分配律就可以推出，若将AddRoundKey移至InvMixColumns后，新的RoundKey应为原RoundKey乘上同样的4×4矩阵，才能保证运算结果不变。

再仔细观察解密的流程图，第0个轮密钥直接异或，最后一个轮密钥在解密的尾轮中，这两个轮密钥均不涉及InvMixcolumns的交换，因此在等价解密的过程中，除了需要将加密的轮密钥逆序外，第1~第n-1个轮密钥应先进行InvMixColumns，变换成解密用密钥。

AES加密和等价解密的轮之间具有一种奇特的对称美学，但轮密钥不同，这是AES的设计中第二个违反直觉的地方。

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

    MEOW_SHUFFLE_INV(xmm3, xmm4, xmm5, xmm7, xmm0, xmm1);
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
```





# 结果展示

![image](https://user-images.githubusercontent.com/75195549/182007634-8e4f47cb-2b57-49f8-a9df-d60ff2313316.png)




