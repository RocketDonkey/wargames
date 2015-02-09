#### io.smashthestack.org
Writeups for wargames found at http://io.smashthestack.org/.

As the instructions indicate, all levels are found under `/levels`, and the
general pattern is that the username you used to log in is the name of the
binary/source you'll be using to try to read the password of the next level's
user.

The idea is that each binary is a `setuid` binary, where the owner is
`level(n+1)` (`n` being the current level). This means that commands within the
binary are executed as user `level(n+1)`, and therefore if you can get the
binary to drop you into a shell, it will be as user `level(n+1)`. You can then
read that user's password from `/home/level(n+1)/.pass`. 

For each level, I create a very (very) basic login script that uses
[`sshpass`](http://linux.die.net/man/1/sshpass):

```bash
#!/bin/sh
sshpass -p 'current_level_password' ssh level#@io.smashthestack.org
```

The only reason for this is to simplify logging in as you don't need to type as
much (or remember the password). One important thing to note: the passwords do
occasionally change, so you may come back in a few days/weeks/months to discover
that you can no longer log in.  Therefore if you are working on a challenge and
can no longer log in, the password may have changed (in which case you can go
back through your scripts and generate the new passwords).
