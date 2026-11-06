+++
date = '2026-11-06T20:08:49+08:00'
draft = false
title = 'Shellcode'
tags = ["shellcode"]
categories = ["CTF"]
description = "当遇到的ret2shellcode题型越来越难以一次性通过`shellcraft`来解决，我们需要学会精打细算......"
+++

## 清零rax/ezx

|汇编|字节数|用途|
|---|---|---|
|xor rax,rax|3字节|清零（一般不用）|
|xor eax,eax|2字节|清零（高位也清）|

## 清零rdx

|汇编|字节数|用途|
|---|---|---|
|cdq|1字节|rax非负时，rdx清零|
|xor edx,edx|2字节|清零rdx|
|xor rdx,rdx|3字节|清零rdx|

补充：再`x86-64`下，任何对32位寄存器的写入都会自动把高32位清零，因此`xor edx,edx`（机器码`31 D2`,2字节）同样能完整清零rdx，比`xor rdx,rdx`还少1字节，也是常用替代方案

## 赋值rdx为59

当我们试图调用`execve`时,需要往寄存器rax传入59，有如下三种方式：

|汇编|字节数|机器码|
|---|---|---|
|mov eax,59|5字节|B8 3B 00 00 00|

一共5字节

|汇编|字节数|机器码|
|---|---|---|
|xor eax,eax|2字节|6A 3B|
|mov al,59|2字节|B0 3B|

一共4字节

|汇编|字节数|机器码|
|---|---|---|
|push 59|2字节|6A 3B|
|pop rax|1字节|5B|

（注意这里不可以写成eax，因为不合规）

一共3字节

所以用哪个还要说吗

## 常见寄存器

|64位|32位|16位|低8位|高8位|

|---|---|---|---|---|
|rax|eax|ax|al|ah|
|rbx|ebx|bx|bl|bh|
|rcx|ecx|cx|cl|ch|
|rdx|edx|dx|dl|dh|
|rsi|esi|si|sil|---|
|rdi|edi|di|dil|---|