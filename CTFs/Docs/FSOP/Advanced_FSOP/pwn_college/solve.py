#!/usr/bin/env python3

from pwn import *

exe = ELF("./demo1_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

gdbscript = '''
b 30

'''
def conn():
    if args.LOCAL:
        r = gdb.debug([exe.path], gdbscript)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    # leak win address
    r.recvuntil(b'win func is located at: ')
    win = int(r.recvline().strip(), 16)
    log.info(f"win: {hex(win)}")
    
    # leak libc address
    r.recvuntil(b'puts is located at: ')
    puts = int(r.recvline().strip(), 16)
    log.info(f"puts: {hex(puts)}")
    libc_base = puts - libc.sym.puts
    libc.address = libc_base
    log.info(f"libc base: {hex(libc_base)}")
    
    # leak stack address
    r.recvuntil(b'Reading into stack buff located at: ')
    stack_leak = int(r.recvline().strip(), 16)
    log.info(f"stack leak: {hex(stack_leak)}")
    
    
    # good luck pwning :)

    
    r.interactive()


if __name__ == "__main__":
    main()
