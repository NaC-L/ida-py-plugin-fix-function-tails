import ida_kernwin
import idautils
import idaapi
import idc
import ida_idaapi


class function_tail(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Fix function tail"
    help = ""
    wanted_name = "FunctionTailFix"
    wanted_hotkey = "CTRL+B"






    def getblockend(self,adr,curfunc = None):
        while True:
            targetfunc = idaapi.get_func(adr)

            
            mnem = idaapi.print_insn_mnem(adr)
            if mnem == "jmp":
                return (adr)
            

            if targetfunc != None:
                return adr

            adr = self.nextinstruction(adr)

    def whereitpoints(self,sel):
        print("getting blockend",hex(sel))
        sel = self.getblockend(sel)
        print("sel",sel)
        print(type(sel))
        if sel == None:
            return None
        mnem = idaapi.print_insn_mnem(sel)
        if mnem == "jmp" or mnem == "jz" or mnem == "jnz":
            opnd = idaapi.print_operand(sel, 0)
            target = opnd.split("loc_")[1][:8]
            print("Selected instruction is a jmp to 0x"+target)
            targetint = int(target,16)
            func = idaapi.get_func(sel)
            targetfunc = idaapi.get_func(targetint)
            print(targetint)
            if targetfunc == None:
                print("not linked")
                return targetint
            if idaapi.get_func_name(func.start_ea) == idaapi.get_func_name(targetfunc.start_ea):
                print("everything good")
                return None

    def nextinstruction(self,adr):
        
        targetint = adr
        if type(adr) != type(1):
            targetint = int(adr,16)
        size = idaapi.get_item_size(adr)
        return adr + size

    def appendit(self,addr,func):
        if addr == None or func == None:
            return
        blockend = self.getblockend(addr)
        print(idaapi.append_func_tail(func,addr, self.nextinstruction(blockend) ))
        print("linked it ",hex(addr))
        return self.appendit(self.whereitpoints(blockend),func)

    

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        # Retrieve the current cursor position

        sel = idaapi.get_screen_ea()
        mnem = idaapi.print_insn_mnem(sel)
        if mnem == "jmp" or mnem == "jz" or mnem == "jnz" or mnem == "jbe" :
            opnd = idaapi.print_operand(sel, 0)
            target = opnd.split("loc_")[1][:8]
            print("Selected instruction is a jmp to 0x"+target)
            targetint = int(target,16)
            func = idaapi.get_func(sel)
            targetfunc = idaapi.get_func(targetint)
            if targetfunc == None:
                print("not linked")
                return self.appendit(targetint,func)
            if idaapi.get_func_name(func.start_ea) == idaapi.get_func_name(targetfunc.start_ea):
                print("everything good")
                return

        

    def term(self):
        pass

def PLUGIN_ENTRY():
    return function_tail()
