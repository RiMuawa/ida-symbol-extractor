from idc import *
from idautils import *
from ida_bytes import *
from ida_name import set_name
from ida_funcs import add_func, get_func
from ida_kernwin import msg, ask_addr

# gpt tell me that before ida6.x should use this api
cur_ea = ScreenEA()

start_addr = ask_addr(cur_ea, "Please enter the start address:")
end_addr = ask_addr(cur_ea, "Please enter the end address:")

if start_addr is None or end_addr is None:
    msg("User cancelled input. Script terminated.\n")
else:
    if start_addr > end_addr:
        msg("Error: Start address must be less than or equal to end address.\n")
    else:
        addr = start_addr
        while addr + 8 <= end_addr:
            str_ptr  = get_wide_dword(addr)
            func_ptr = get_wide_dword(addr + 4)

            func_name = get_strlit_contents(str_ptr, -1, STRTYPE_C)
            if not func_name:
                msg("Skipping %X: Invalid string address %X\n" % (addr, str_ptr))
                addr += 8
                continue

            func_name = func_name.decode('utf-8', errors='ignore')

            if not set_name(func_ptr, func_name, SN_CHECK):
                msg("Failed to name: %X -> %s\n" % (func_ptr, func_name))
            else:
                msg("Named function %X as %s\n" % (func_ptr, func_name))

            if not get_func(func_ptr):
                add_func(func_ptr)

            addr += 8
