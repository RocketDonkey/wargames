#### io.smashthestack.org - Level 1

You are given the password to the first level on the
http://io.smashthestack.org/ homepage (`level1`), so create our `login.sh` for
this level:

```bash
#!/bin/sh
sshpass -p 'level1' ssh level1@io.smashthestack.org
```

Running `login.sh` will log us into the box, and navigating to `/levels` and
listing the contents of the directory will show us all of level files. The one
we are interested in is `level01`, and after running it we see that it is
looking for a 3-digit password:

```bash
level1@io:/levels$ ./level01 
Enter the 3 digit passcode to enter: 111
level1@io:/levels$ 
```

Since we don't have any source code for this level, let's try using `objdump`
(part of [`binutils`](http://www.gnu.org/software/binutils/)) to take a look at
the disassembly:

```objdump
level1@io:/levels$ objdump -D -M intel -j .text level01

level01:     file format elf32-i386


Disassembly of section .text:

08048080 <_start>:
 8048080:       68 28 91 04 08          push   0x8049128
 8048085:       e8 85 00 00 00          call   804810f <puts>
 804808a:       e8 10 00 00 00          call   804809f <fscanf>
 804808f:       3d 0f 01 00 00          cmp    eax,0x10f
 8048094:       0f 84 42 00 00 00       je     80480dc <YouWin>
 804809a:       e8 64 00 00 00          call   8048103 <exit>
```

The call to `fscanf` above is where our input is read. Our response is stored in
register `eax`, and then the value is compared with a constant value `0x10f`. If
our input matches the constant, we jump to `YouWin` (which seems like something
we'd want to do). However since the constant above is in hexadecimal, and we
need it in base-10 (which is the 'normal' counting system), let's convert
`0x10f` to base-10. Here are two ways you could do that - one with Bash, one
with Python:

```Bash
level1@io:/levels$ echo $((16#10f))
271
level1@io:/levels$ python -c "print 0x10f"
271
```

In both cases, the result is `271`, so let's try plugging that in:

```Bash
level1@io:/levels$ ./level01 
Enter the 3 digit passcode to enter: 271
Congrats you found it, now read the password for level2 from /home/level2/.pass
sh-4.2$ id
uid=1001(level1) gid=1001(level1) euid=1002(level2) groups=1002(level2),1001(level1),1029(nosu)
sh-4.2$ cat /home/level2/.pass
3ywr07ZFw5IsdKzU
sh-4.2$
```

Awesome, looks like we found the password for level2. At this point, I'd create
a new directory for `level2`, copy `login.sh` into it and change the contents
to:

```Bash
#!/bin/sh
sshpass -p '3ywr07ZFw5IsdKzU' ssh level2@io.smashthestack.org
```

Then it's time to move to the next level!
