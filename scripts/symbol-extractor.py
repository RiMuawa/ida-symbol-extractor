from idc import *
from idautils import *
from ida_bytes import *
from ida_name import set_name
from ida_funcs import add_func
from ida_funcs import get_func
from ida_kernwin import msg

# set your own address here
start_addr = 0x00
end_addr   = 0x00

addr = start_addr
while addr + 8 <= end_addr:
    str_ptr  = get_wide_dword(addr)
    func_ptr = get_wide_dword(addr + 4)

    func_name = get_strlit_contents(str_ptr, -1, STRTYPE_C)
    if not func_name:
        msg("Skipping %X: Invalid string address %X\n" % (addr, str_ptr))
        addr += 8
        continue

    func_name = func_name.decode('utf-8')

    if not set_name(func_ptr, func_name, SN_CHECK):
        msg("Failed to name: %X -> %s\n" % (func_ptr, func_name))
    else:
        msg("Named function %X as %s\n" % (func_ptr, func_name))

    if not get_func(func_ptr):
        add_func(func_ptr)

    addr += 8
