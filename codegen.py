#!/usr/bin/env python3

"""Code generation methods for all low-level nodes in the IR.
Codegen functions return a string, consisting of the assembly code they
correspond to. Alternatively, they can return a list where:
 - the first element is the assembly code
 - the second element is extra assembly code to be appended at the end of
   the code of the function they are contained in
This feature can be used only by IR nodes that are contained in a Block, and
is used for adding constant literals."""

from datalayout import *
from ir import *


static_const_count = 0


class x86CodeGenerator():
    def __init__(self):
        self.type = 'x86'
        self.REGS_CALLEESAVE = []
        self.REGS_CALLERSAVE = [0, 1, 2, 3]
        self.REG_SCRATCH = 4
        self.REG_FP = 50


        self.map = {
            0: '%rdi',
            1: '%rax',
            2: '%rbx',
            3: '%rcx',
            4: '%rdx',
            self.REG_FP: '%ebp'
        }

    def comment(self, what):
        return f'# {what}\n'


    def format_imm(self, value):
        return f'${value}'


    def get_register_string(self, regid):
        return self.map[regid]


    def save_registers(self, registers):
        res = ''

        if len(registers) > 0:
            for r in registers:
                regstr = self.get_register_string(r)
                res += f'\tpush {regstr}\n'

        return res


    def restore_registers(self, registers):
        res = ''

        if len(registers):
            for r in reversed(registers):
                regstr = self.get_register_string(r)
                res += f'\tpop {regstr}\n'

        return res


    def call_function(self, label):
        return f'\tcall {label}\n'


    def return_from_function(self):
        return '\tret\n'


    def branch(self, label):
        return f'\tj {label}\n'


    def branch_equal(self, label):
        return f'\tjeq {label}\n'


    def branch_not_equal(self, label):
        return f'\tjne {label}\n'


    def test(self, op1, op2):
        op1  = self.get_register_string(op1)
        op2  = self.get_register_string(op2)

        return f'\ttst {op1}, {op2}\n'
    

    def copy_if_different(self, r1, r2):
        if r1 != r2:
            return self.mov_reg_to_reg(r1, r2)
        else:
            return ''


    def compare(self, op1, op2):
        op1  = self.get_register_string(op1)
        op2  = self.get_register_string(op2)

        return f'\tcmp {op1}, {op2}\n'


    def add(self, dest, op1, op2):
        rdest = self.get_register_string(dest)
        return self.copy_if_different(dest, op1) + f'\tadd {op2}, {rdest}\n'


    def addi(self, dest, src, imm):
        rdest = self.get_register_string(dest)
        return self.copy_if_different(dest, src) + f'\tadd ${imm}, {rdest}\n'


    def andi(self, dest, src, imm):
        rdest = self.get_register_string(dest)
        return self.copy_if_different(dest, src) + f'\tand ${imm}, {rdest}\n'


    def sub(self, dest, op1, op2):
        return self.copy_if_different(dest, src) + f'\tsub ${imm}, {dest}\n'


    def subi(self, dest, src, imm):
        dest = self.get_register_string(dest)
        src  = self.get_register_string(src)
        return f'\tsub {src}, ${imm}, {dest}\n'


    def mul(self, dest, op1, op2):
        dest = self.get_register_string(dest)
        op1  = self.get_register_string(op1)
        op2  = self.get_register_string(op2)

        return f'\tmul {op1}, {op2}, {dest}\n'


    def div(self, dest, op1, op2):
        dest = self.get_register_string(dest)
        op1  = self.get_register_string(op1)
        op2  = self.get_register_string(op2)

        return f'\tdiv {op1}, {op2}, {dest}\n'


    def mov_reg_to_reg(self, dest, src):
        dest = self.get_register_string(dest)
        src  = self.get_register_string(src)

        return f'\tmov {src}, {dest}\n'


    def mov_eq(self, dest, imm):
        dest = self.get_register_string(dest)

        return f'\tmoveq ${imm}, {dest}\n'


    def mov_ne(self, dest, imm):
        dest = self.get_register_string(dest)

        return f'\tmovne ${imm}, {dest}\n'


    def mov_lt(self, dest, imm):
        dest = self.get_register_string(dest)

        return f'\tmovlt ${imm}, {dest}\n'


    def mov_gt(self, dest, imm):
        dest = self.get_register_string(dest)

        return f'\tmovgt {dest}, ${imm}, {dest}\n'


    def mov_ge(self, dest, imm):
        dest = self.get_register_string(dest)

        return f'\tmovge ${imm}, {dest}\n'


    def mov_le(self, dest, imm):
        dest = self.get_register_string(dest)

        return f'\tmovle ${imm}, {dest}\n'


    def move_negate(self, dest, src):
        dest = self.get_register_string(dest)
        src  = self.get_register_string(src)

        return f'\tmov {src}, {dest}\n\tneg {dest}\n'


    def load_addr(self, dest, addr):
        dest = self.get_register_string(dest)

        return f'\tmov ${addr}, {dest}\n'


    def load_byte(self, dest, from_where, offset = None):
        dest = self.get_register_string(dest)
        from_where = self.get_register_string(from_where)

        if offset is None:
            return f'\tmovb ({from_where}), {dest}\n'
        else:
            return f'\tmovb ({from_where}, {offset}), {dest}\n'


    def load_halfword(self, dest, from_where, offset = None):
        dest = self.get_register_string(dest)
        from_where = self.get_register_string(from_where)

        if offset is None:
            return f'\tmovh ({from_where}), {dest}\n'
        else:
            return f'\tmovh ({from_where}, {offset}), {dest}\n'


    def load(self, dest, from_where, offset = None):
        dest = self.get_register_string(dest)
        from_where = self.get_register_string(from_where)

        if offset is None:
            return f'\tmov ({from_where}), {dest}\n'
        else:
            return f'\tmov ({from_where}, {offset}), {dest}\n'


    def store(self, what, dest, offset = None):
        dest = self.get_register_string(dest)
        what = self.get_register_string(what)

        if offset is None:
            return f'\tmov {what}, ({dest})\n'
        else:
            return f'\tmov {what}, ({dest}, {offset})\n'


    def store_halfword(self, what, dest, offset = None):
        dest = self.get_register_string(dest)
        what = self.get_register_string(what)

        if offset is None:
            return f'\tmovh {what}, ({dest})\n'
        else:
            return f'\tmovh {what}, ({dest}, {offset})\n'


    def store_byte(self, what, dest, offset = None):
        dest = self.get_register_string(dest)
        what = self.get_register_string(what)

        if offset is None:
            return f'\tmovb {what}, ({dest})\n'
        else:
            return f'\tmovb {what}, ({dest}, {offset})\n'




class ArmCodeGenerator():
    def __init__(self):
        self.type = 'arm'

        self.REG_FP = 11
        self.REG_SCRATCH = 12
        self.REG_SP = 13
        self.REG_LR = 14
        self.REG_PC = 15

        self.REGS_CALLEESAVE = [4, 5, 6, 7, 8, 9, 10]
        self.REGS_CALLERSAVE = [0, 1, 2, 3]


    def comment(self, what):
        return f'\t@ {what}\n'


    def format_imm(self, value):
        return f'#{value}'


    def get_register_string(self, regid):
        if   regid == REG_LR:
            return 'lr'
        elif regid == REG_SP:
            return 'sp'
        else:
            return f'r{regid}'


    def save_registers(self, registers):
        if len(registers):
            line = '\tpush {' + self.get_register_string(registers[0])

            for reg in registers[1:]:
                line = line + f', {self.get_register_string(reg)}'

            return line + '}\n'
        else:
            return ''


    def restore_registers(self, registers):
        if len(registers):
            line = '\tpop {' + self.get_register_string(registers[0])

            for reg in registers[1:]:
                line = line + f', {self.get_register_string(reg)}'

            return line + '}\n'
        else:
            return ''


    def call_function(self, label):
        # TODO: we might need to save some registers into the stack
        return f'\tbl {label}\n'


    def return_from_function(self):
        return '\tbx lr\n'


    def branch(self, label):
        return f'\tb {label}\n'


    def branch_equal(self, label):
        return f'\tbeq {label}\n'


    def branch_not_equal(self, label):
        return f'\tbne {label}\n'


    def test(self, op1, op2):
        op1  = self.get_register_string(op1)
        op2  = self.get_register_string(op2)

        return f'\ttst {op1}, {op2}\n'


    def compare(self, op1, op2):
        op1  = self.get_register_string(op1)
        op2  = self.get_register_string(op2)

        return f'\tcmp {op1}, {op2}\n'


    def add(self, dest, op1, op2):
        dest = self.get_register_string(dest)
        op1  = self.get_register_string(op1)
        op2  = self.get_register_string(op2)

        if dest == op1:
            return f'\tadd {dest}, {op2}\n'
        else:
            return f'\tadd {dest}, {op1}, {op2}\n'


    def addi(self, dest, src, imm):
        dest = self.get_register_string(dest)
        src  = self.get_register_string(src)
        return f'\tadd {dest}, {src}, #{imm}\n'


    def andi(self, dest, src, imm):
        dest = self.get_register_string(dest)
        src  = self.get_register_string(src)
        return f'\tand {dest}, {src}, #{imm}\n'


    def sub(self, dest, op1, op2):
        dest = self.get_register_string(dest)
        op1  = self.get_register_string(op1)
        op2  = self.get_register_string(op2)

        return f'\tsub {dest}, {op1}, {op2}\n'


    def subi(self, dest, src, imm):
        dest = self.get_register_string(dest)
        src  = self.get_register_string(src)
        return f'\tsub {dest}, {src}, #{imm}\n'


    def mul(self, dest, op1, op2):
        dest = self.get_register_string(dest)
        op1  = self.get_register_string(op1)
        op2  = self.get_register_string(op2)

        return f'\tmul {dest}, {op1}, {op2}\n'


    def div(self, dest, op1, op2):
        dest = self.get_register_string(dest)
        op1  = self.get_register_string(op1)
        op2  = self.get_register_string(op2)

        return f'\tdiv {dest}, {op1}, {op2}\n'


    def mov_reg_to_reg(self, dest, src):
        dest = self.get_register_string(dest)
        src  = self.get_register_string(src)

        return f'\tmov {dest}, {src}\n'


    def mov_eq(self, dest, imm):
        dest = self.get_register_string(dest)

        return f'\tmoveq {dest}, #{imm}\n'


    def mov_ne(self, dest, imm):
        dest = self.get_register_string(dest)

        return f'\tmovne {dest}, #{imm}\n'


    def mov_lt(self, dest, imm):
        dest = self.get_register_string(dest)

        return f'\tmovlt {dest}, #{imm}\n'


    def mov_gt(self, dest, imm):
        dest = self.get_register_string(dest)

        return f'\tmovgt {dest}, #{imm}\n'


    def mov_ge(self, dest, imm):
        dest = self.get_register_string(dest)

        return f'\tmovge {dest}, #{imm}\n'


    def mov_le(self, dest, imm):
        dest = self.get_register_string(dest)

        return f'\tmovle {dest}, #{imm}\n'


    def move_negate(self, dest, src):
        dest = self.get_register_string(dest)
        src  = self.get_register_string(src)

        return f'\tmvn {dest}, {src}\n'


    def load_addr(self, dest, addr):
        dest = self.get_register_string(dest)

        return f'\tldr {dest}, {addr}\n'


    def load_byte(self, dest, from_where, offset = None):
        dest = self.get_register_string(dest)
        from_where = self.get_register_string(from_where)

        if offset is None:
            return f'\tldrb {dest}, [{from_where}]\n'
        else:
            return f'\tldrb {dest}, [{from_where}, #{offset}]\n'


    def load_halfword(self, dest, from_where, offset = None):
        dest = self.get_register_string(dest)
        from_where = self.get_register_string(from_where)

        if offset is None:
            return f'\tldrh {dest}, [{from_where}]\n'
        else:
            return f'\tldrh {dest}, [{from_where}, #{offset}]\n'


    def load(self, dest, from_where, offset = None):
        dest = self.get_register_string(dest)
        from_where = self.get_register_string(from_where)

        if offset is None:
            return f'\tldr {dest}, [{from_where}]\n'
        else:
            return f'\tldr {dest}, [{from_where}, #{offset}]\n'


    def store(self, what, dest, offset = None):
        dest = self.get_register_string(dest)
        what = self.get_register_string(what)

        if offset is None:
            return f'\tstr {what}, [{dest}]\n'
        else:
            return f'\tstr {what}, [{dest}, #{offset}]\n'


    def store_halfword(self, what, dest, offset = None):
        dest = self.get_register_string(dest)
        what = self.get_register_string(what)

        if offset is None:
            return f'\tstrh {what}, [{dest}]\n'
        else:
            return f'\tstrh {what}, [{dest}, #{offset}]\n'


    def store_byte(self, what, dest, offset = None):
        dest = self.get_register_string(dest)
        what = self.get_register_string(what)

        if offset is None:
            return f'\tstrb {what}, [{dest}]\n'
        else:
            return f'\tstrb {what}, [{dest}, #{offset}]\n'


def new_local_const(val):
    global static_const_count

    label = f'.const{static_const_count}'
    trail = f'{label}:\n\t.word {val}\n'

    static_const_count += 1

    return label, trail


def symbol_codegen(self, regalloc, generator):
    if self.allocinfo is None:
        return ""
    if not isinstance(self.allocinfo, LocalSymbolLayout):
        return '\t.comm ' + self.allocinfo.symname + ', ' + repr(self.allocinfo.bsize) + "\n"
    else:
        return '\t.equ ' + self.allocinfo.symname + ', ' + repr(self.allocinfo.fpreloff) + "\n"


def irnode_codegen(self, regalloc, generator):
    res = [generator.comment("irnode " + repr(id(self)) + ' type ' + repr(type(self))), '']
    if 'children' in dir(self) and len(self.children):
        for node in self.children:
            try:
                try:
                    labl = node.get_label()
                    res[0] += labl.name + ':\n'
                except Exception:
                    pass
                res = codegen_append(res, node.codegen(regalloc, generator))
            except Exception as e:
                res[0] += "\t" + generator.comment("node " + repr(id(node)) + repr(type(node)) + " did not generate any code")
                res[0] += "\t" + generator.comment("exc: " + repr(e))
    return res


def block_codegen(self, regalloc, generator):
    res = [generator.comment('block'), '']
    for sym in self.symtab:
        res = codegen_append(res, sym.codegen(regalloc, generator))

    if self.parent is None:
        res[0] += '\t.global __pl0_start\n'
        res[0] += "__pl0_start:\n"

    if generator.type == 'arm':
        res[0] += generator.save_registers(REGS_CALLEESAVE + [REG_FP, REG_LR])
        res[0] += generator.mov_reg_to_reg(REG_FP, REG_SP)
        stacksp = self.stackroom + regalloc.spill_room()
        res[0] += generator.subi(REG_SP, REG_SP, stacksp)

    regalloc.enter_function_body(self)
    try:
        res = codegen_append(res, self.body.codegen(regalloc, generator))
    except Exception:
        pass

    if generator.type == 'arm':
        res[0] += generator.mov_reg_to_reg(REG_SP, REG_FP)
        res[0] += generator.restore_registers(REGS_CALLEESAVE + [REG_FP, REG_LR])

    res[0] += generator.return_from_function()

    res[0] = res[0] + res[1]
    res[1] = ''

    try:
        res = codegen_append(res, self.defs.codegen(regalloc, generator))
    except Exception:
        pass

    return res[0] + res[1]


def deflist_codegen(self, regalloc, generator):
    return ''.join([child.codegen(regalloc, generator) for child in self.children])


def fun_codegen(self, regalloc, generator):
    res = '\n' + self.symbol.name + ':\n'
    res += self.body.codegen(regalloc, generator)
    return res


def binstat_codegen(self, regalloc, generator):
    res = generator.comment(f'binstat {id(self)} of type {type(self)}')
    res += regalloc.gen_spill_load_if_necessary(self.srca, generator)
    res += regalloc.gen_spill_load_if_necessary(self.srcb, generator)
    ra = regalloc.get_register_for_variable(self.srca)
    rb = regalloc.get_register_for_variable(self.srcb)
    rd = regalloc.get_register_for_variable(self.dest)

    if self.op == "plus":
        res += generator.add(rd, ra, rb)
    elif self.op == "minus":
        res += generator.sub(rd, ra, rb)
    elif self.op == "times":
        res += generator.mul(rd, ra, rb)
    elif self.op == "slash":
        res += generator.div(rd, ra, rb)
    elif self.op == "eql":
        res += generator.compare(ra, rb)
        res += generator.mov_eq(rd, 1)
        res += generator.mov_ne(rd, 0)
    elif self.op == "neq":
        res += generator.compare(ra, rb)
        res += generator.mov_eq(rd, 0)
        res += generator.mov_ne(rd, 1)
    elif self.op == "lss":
        res += generator.compare(ra, rb)
        res += generator.mov_lt(rd, 1)
        res += generator.mov_ge(rd, 0)
    elif self.op == "leq":
        res += generator.compare(ra, rb)
        res += generator.mov_le(rd, 1)
        res += generator.mov_gt(rd, 0)
    elif self.op == "gtr":
        res += generator.compare(ra, rb)
        res += generator.mov_gt(rd, 1)
        res += generator.mov_le(rd, 0)
    elif self.op == "geq":
        res += generator.compare(ra, rb)
        res += generator.mov_ge(rd, 1)
        res += generator.mov_lt(rd, 0)
    else:
        raise Exception("operation " + repr(self.op) + " unexpected")
    return res + regalloc.gen_spill_store_if_necessary(self.dest, generator)


def print_codegen(self, regalloc, generator):
    res = generator.comment(f'print {id(self)} of type {type(self)}')
    res += regalloc.gen_spill_load_if_necessary(self.src, generator)
    rp = regalloc.get_register_for_variable(self.src)
    res += generator.save_registers(generator.REGS_CALLERSAVE)
    res += generator.mov_reg_to_reg(0, rp)
    res += generator.call_function('__pl0_print')
    res += generator.restore_registers(generator.REGS_CALLERSAVE)
    return res


def read_codegen(self, regalloc, generator):
    res = generator.comment(f'read {id(self)} of type {type(self)}')
    rd = regalloc.get_register_for_variable(self.dest)

    # punch a hole in the saved registers if one of them is the destination
    # of this "instruction"
    savedregs = list(generator.REGS_CALLERSAVE)
    if len(savedregs) > 0 and regalloc.vartoreg[self.dest] in savedregs:
        savedregs.remove(regalloc.vartoreg[self.dest])

    res += generator.save_registers(savedregs)
    res += generator.call_function('__pl0_read')
    res += generator.mov_reg_to_reg(rd, 0)
    res += generator.restore_registers(savedregs)
    res += regalloc.gen_spill_store_if_necessary(self.dest, generator)
    return res


def branch_codegen(self, regalloc, generator):
    res = generator.comment(f'branch {id(self)} of type {type(self)}')

    targetl = self.target.name
    if not self.returns:
        if self.cond is None:
            return generator.branch(targetl)
        else:
            res += regalloc.gen_spill_load_if_necessary(self.cond, generator)
            rcond = regalloc.get_register_for_variable(self.cond)
            res += generator.test(rcond, rcond)

            if self.negcond:
                return res + generator.branch_equal(targetl)
            else:
                return res + generator.branch_not_equal(targetl)
    else:
        if self.cond is None:
            res += generator.save_registers(generator.REGS_CALLERSAVE)
            res += generator.call_function(targetl)
            res += generator.restore_registers(generator.REGS_CALLERSAVE)
            return res
        else:
            Exception("Not understood this part")
            res += regalloc.gen_spill_load_if_necessary(self.cond, generator)
            rcond = regalloc.get_register_for_variable(self.cond)
            res += generator.test(rcond, rcond)
            res += '\t' + ('bne' if self.negcond else 'beq') + ' ' + rcond + ', 1f\n'
            res += generator.save_registers(generator.REGS_CALLERSAVE)
            res += generator.call_function(targetl)
            res += generator.restore_registers(generator.REGS_CALLERSAVE)
            res += '1:'
            return res
    return generator.comment('impossible!')


def emptystat_codegen(self, regalloc, generator):
    return generator.comment('emptystat')


def ldptrto_codegen(self, regalloc, generator):
    res = generator.comment(f'ldptrto {id(self)} of type {type(self)}')
    rd = regalloc.get_register_for_variable(self.dest)

    trail = ''
    ai = self.symbol.allocinfo
    if type(ai) is LocalSymbolLayout:
        off = ai.fpreloff
        if off > 0:
            res += generator.addi(rd, REG_FP, off)
        else:
            res += generator.subi(rd, REG_FP, -off)
    else:
        lab, tmp = new_local_const(ai.symname)
        trail += tmp
        res += generator.load_addr(rd, lab)
    return [res + regalloc.gen_spill_store_if_necessary(self.dest, generator), trail]


# TODO: the actual difficult part of this file
def storestat_codegen(self, regalloc, generator):
    res = generator.comment(f'storestat {id(self)} of type {type(self)}')
    trail = ''

    dest = None
    offset = None


    if self.dest.alloct == 'reg':
        res += regalloc.gen_spill_load_if_necessary(self.dest, generator)
        dest = regalloc.get_register_for_variable(self.dest)
    else:
        ai = self.dest.allocinfo
        if type(ai) is LocalSymbolLayout:
            dest = generator.REG_FP
            offset = ai.symname

            # dest = '[' + generator.get_register_string(REG_FP) + ', #' + ai.symname + ']'
        else:
            lab, tmp = new_local_const(ai.symname)
            trail += tmp
            res += generator.load_addr(generator.REG_SCRATCH, lab)
            dest = generator.REG_SCRATCH
            # dest = '[' + generator.get_register_string(REG_SCRATCH) + ']'

    if type(self.dest.stype) is PointerType:
        desttype = self.dest.stype.pointstotype
    else:
        desttype = self.dest.stype
    typeid = ['b', 'h', None, ''][desttype.size // 8 - 1]
    if typeid != '' and 'unsigned' in desttype.qual_list:
        typeid = 's' + type

    res += regalloc.gen_spill_load_if_necessary(self.symbol, generator)
    rsrc = regalloc.get_register_for_variable(self.symbol)


    if typeid == 'b':
        res += generator.store_byte(rsrc, dest, offset)
    elif typeid == 'h':
        res += generator.store_halfword(rsrc, dest, offset)
    elif typeid is None or typeid == '':
        res += generator.store(rsrc, dest, offset)
    else:
        Exception(typeid)


    return [res, trail]


def loadstat_codegen(self, regalloc, generator):
    res = generator.comment(f'loadstat {id(self)} of type {type(self)}')
    trail = ''

    source = None
    offset = None


    if self.symbol.alloct == 'reg':
        res += regalloc.gen_spill_load_if_necessary(self.symbol, generator)
        source = regalloc.get_register_for_variable(self.symbol)

        # src = '[' + generator.get_register_string(regalloc.get_register_for_variable(self.symbol)) + ']'
    else:
        ai = self.symbol.allocinfo
        if type(ai) is LocalSymbolLayout:
            source = generator.REG_FP
            offset = ai.symname

            # src = '[' + generator.get_register_string(REG_FP) + ', #' + ai.symname + ']'
        else:
            lab, tmp = new_local_const(ai.symname)
            trail += tmp
            res += generator.load_addr(generator.REG_SCRATCH, lab)

            source = generator.REG_SCRATCH
            # src = '[' + generator.get_register_string(REG_SCRATCH) + ']'

    if type(self.symbol.stype) is PointerType:
        desttype = self.symbol.stype.pointstotype
    else:
        desttype = self.symbol.stype
    typeid = ['b', 'h', None, ''][desttype.size // 8 - 1]
    if typeid != '' and 'unsigned' in desttype.qual_list:
        typeid = 's' + type

    rdst = regalloc.get_register_for_variable(self.dest)

    if typeid == 'b':
        res += generator.load_byte(rdst, source, offset)
    elif typeid == 'h':
        res += generator.load_halfword(rdst, source, offset)
    elif typeid is None or typeid == '':
        res += generator.load(rdst, source, offset)
    else:
        Exception(typeid)
    
    res += regalloc.gen_spill_store_if_necessary(self.dest, generator)
    return [res, trail]


def loadimm_codegen(self, regalloc, generator):
    res = generator.comment(f'loadimm {id(self)} of type {type(self)}')
    rd = regalloc.get_register_for_variable(self.dest)

    val = self.val
    if val >= -256 and val < 256:
        if val < 0:
            res += generator.move_negate(rd, -val - 1)
        else:
            # workaround
            res += generator.sub(rd, rd, rd)
            res += generator.addi(rd, rd, val)

        trail = ''
    else:
        lab, trail = new_local_const(repr(val))
        res += generator.load_addr(rd, lab)
    return [res + regalloc.gen_spill_store_if_necessary(self.dest, generator), trail]


def unarystat_codegen(self, regalloc, generator):
    res = generator.comment(f'unarystat {id(self)} of type {type(self)}')
    res += regalloc.gen_spill_load_if_necessary(self.src, generator)
    rs = regalloc.get_register_for_variable(self.src)
    rd = regalloc.get_register_for_variable(self.dest)
    if self.op == 'plus':
        if rs != rd:
            res += generator.mov_reg_to_reg(rd, rs)
    elif self.op == 'minus':
        res += generator.move_negate(rd, rs)
        res += generator.addi(rd, rd, 1)
    elif self.op == 'odd':
        res += generator.andi(rd, rs, 1)
    else:
        raise Exception("operation " + repr(self.op) + " unexpected")
    res += regalloc.gen_spill_store_if_necessary(self.dest, generator)
    return res


def generate_code(program, regalloc, code_generator):
    res = '\t.text\n'

    if code_generator.type == 'arm':
        res += '\t.arch armv6\n'
        res += '\t.syntax unified\n'

    return res + program.codegen(regalloc, code_generator)


Symbol        .codegen = symbol_codegen
IRNode        .codegen = irnode_codegen
Block         .codegen = block_codegen
DefinitionList.codegen = deflist_codegen
FunctionDef   .codegen = fun_codegen
BinStat       .codegen = binstat_codegen
PrintCommand  .codegen = print_codegen
ReadCommand   .codegen = read_codegen
BranchStat    .codegen = branch_codegen
EmptyStat     .codegen = emptystat_codegen
LoadPtrToSym  .codegen = ldptrto_codegen
StoreStat     .codegen = storestat_codegen
LoadStat      .codegen = loadstat_codegen
LoadImmStat   .codegen = loadimm_codegen
UnaryStat     .codegen = unarystat_codegen
