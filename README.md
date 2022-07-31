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

# 结果展示

![image](https://user-images.githubusercontent.com/75195549/182007634-8e4f47cb-2b57-49f8-a9df-d60ff2313316.png)




