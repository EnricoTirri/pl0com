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


class ArmCodeGenerator():
    def __init__(self):
        self.calleesave = [4, 5, 6, 7, 8, 9, 10]
        self.callersave = [0, 1, 2, 3]


    def comment(self, what):
        return f'@ {what}'


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
    res = ['\t' + comment("irnode " + repr(id(self)) + ' type ' + repr(type(self))), '']
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
                res[0] += "\t" + comment("node " + repr(id(node)) + " did not generate any code")
                res[0] += "\t" + comment("exc: " + repr(e))
    return res


def block_codegen(self, regalloc, generator):
    res = [comment('block'), '']
    for sym in self.symtab:
        res = codegen_append(res, sym.codegen(regalloc, generator))

    if self.parent is None:
        res[0] += '\t.global __pl0_start\n'
        res[0] += "__pl0_start:\n"

    res[0] += generator.save_registers(REGS_CALLEESAVE + [REG_FP, REG_LR])
    res[0] += '\tmov ' + generator.get_register_string(REG_FP) + ', ' + generator.get_register_string(REG_SP) + '\n'
    stacksp = self.stackroom + regalloc.spill_room()
    res[0] += '\tsub ' + generator.get_register_string(REG_SP) + ', ' + generator.get_register_string(REG_SP) + ', #' + repr(stacksp) + '\n'

    regalloc.enter_function_body(self)
    try:
        res = codegen_append(res, self.body.codegen(regalloc, generator))
    except Exception:
        pass

    res[0] += '\tmov ' + generator.get_register_string(REG_SP) + ', ' + generator.get_register_string(REG_FP) + '\n'
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
    res = regalloc.gen_spill_load_if_necessary(self.srca)
    res += regalloc.gen_spill_load_if_necessary(self.srcb)
    ra = regalloc.get_register_for_variable(self.srca)
    rb = regalloc.get_register_for_variable(self.srcb)
    rd = regalloc.get_register_for_variable(self.dest)
    param = ra + ', ' + rb
    if self.op == "plus":
        res += '\tadd ' + rd + ', ' + param + '\n'
    elif self.op == "minus":
        res += '\tsub ' + rd + ', ' + param + '\n'
    elif self.op == "times":
        res += '\tmul ' + rd + ', ' + param + '\n'
    elif self.op == "slash":
        res += '\tdiv ' + rd + ', ' + param + '\n'
    elif self.op == "eql":
        res += '\tcmp ' + param + '\n'
        res += '\tmoveq ' + rd + ', #1\n'
        res += '\tmovne ' + rd + ', #0\n'
    elif self.op == "neq":
        res += '\tcmp ' + param + '\n'
        res += '\tmoveq ' + rd + ', #0\n'
        res += '\tmovne ' + rd + ', #1\n'
    elif self.op == "lss":
        res += '\tcmp ' + param + '\n'
        res += '\tmovlt ' + rd + ', #1\n'
        res += '\tmovge ' + rd + ', #0\n'
    elif self.op == "leq":
        res += '\tcmp ' + param + '\n'
        res += '\tmovle ' + rd + ', #1\n'
        res += '\tmovgt ' + rd + ', #0\n'
    elif self.op == "gtr":
        res += '\tcmp ' + param + '\n'
        res += '\tmovgt ' + rd + ', #1\n'
        res += '\tmovle ' + rd + ', #0\n'
    elif self.op == "geq":
        res += '\tcmp ' + param + '\n'
        res += '\tmovge ' + rd + ', #1\n'
        res += '\tmovlt ' + rd + ', #0\n'
    else:
        raise Exception("operation " + repr(self.op) + " unexpected")
    return res + regalloc.gen_spill_store_if_necessary(self.dest)


def print_codegen(self, regalloc, generator):
    res = regalloc.gen_spill_load_if_necessary(self.src)
    rp = regalloc.get_register_for_variable(self.src)
    res += generator.save_registers(REGS_CALLERSAVE)
    res += '\tmov ' + generator.get_register_string(0) + ', ' + rp + '\n'
    res += generator.call_function('__pl0_print')
    res += generator.restore_registers(REGS_CALLERSAVE)
    return res


def read_codegen(self, regalloc, generator):
    rd = regalloc.get_register_for_variable(self.dest)

    # punch a hole in the saved registers if one of them is the destination
    # of this "instruction"
    savedregs = list(REGS_CALLERSAVE)
    if regalloc.vartoreg[self.dest] in savedregs:
        savedregs.remove(regalloc.vartoreg[self.dest])

    res = generator.save_registers(savedregs)
    res += generator.call_function('__pl0_read')
    res += '\tmov ' + rd + ', ' + generator.get_register_string(0) + '\n'
    res += generator.restore_registers(savedregs)
    res += regalloc.gen_spill_store_if_necessary(self.dest)
    return res


def branch_codegen(self, regalloc, generator):
    targetl = self.target.name
    if not self.returns:
        if self.cond is None:
            return generator.branch(targetl)
        else:
            res = regalloc.gen_spill_load_if_necessary(self.cond)
            rcond = regalloc.get_register_for_variable(self.cond)
            res += '\ttst ' + rcond + ', ' + rcond + '\n'

            if self.negcond:
                return res + generator.branch_equal(targetl)
            else:
                return res + generator.branch_not_equal(targetl)
    else:
        if self.cond is None:
            res = generator.save_registers(REGS_CALLERSAVE)
            res += generator.call_function(targetl)
            res += generator.restore_registers(REGS_CALLERSAVE)
            return res
        else:
            Exception("Not understood this part")
            res = regalloc.gen_spill_load_if_necessary(self.cond)
            rcond = regalloc.get_register_for_variable(self.cond)
            res += '\ttst ' + rcond + ', ' + rcond + '\n'
            res += '\t' + ('bne' if self.negcond else 'beq') + ' ' + rcond + ', 1f\n'
            res += generator.save_registers(REGS_CALLERSAVE)
            res += generator.call_function(targetl)
            res += generator.restore_registers(REGS_CALLERSAVE)
            res += '1:'
            return res
    return comment('impossible!')


def emptystat_codegen(self, regalloc, generator):
    return '\t' + comment('emptystat')


def ldptrto_codegen(self, regalloc, generator):
    rd = regalloc.get_register_for_variable(self.dest)
    res = ''
    trail = ''
    ai = self.symbol.allocinfo
    if type(ai) is LocalSymbolLayout:
        off = ai.fpreloff
        if off > 0:
            res = '\tadd ' + rd + ', ' + generator.get_register_string(REG_FP) + ', #' + repr(off) + '\n'
        else:
            res = '\tsub ' + rd + ', ' + generator.get_register_string(REG_FP) + ', #' + repr(-off) + '\n'
    else:
        lab, tmp = new_local_const(ai.symname)
        trail += tmp
        res = '\tldr ' + rd + ', ' + lab + '\n'
    return [res + regalloc.gen_spill_store_if_necessary(self.dest), trail]


def storestat_codegen(self, regalloc, generator):
    res = ''
    trail = ''
    if self.dest.alloct == 'reg':
        res += regalloc.gen_spill_load_if_necessary(self.dest)
        dest = '[' + regalloc.get_register_for_variable(self.dest) + ']'
    else:
        ai = self.dest.allocinfo
        if type(ai) is LocalSymbolLayout:
            dest = '[' + generator.get_register_string(REG_FP) + ', #' + ai.symname + ']'
        else:
            lab, tmp = new_local_const(ai.symname)
            trail += tmp
            res += '\tldr ' + generator.get_register_string(REG_SCRATCH) + ', ' + lab + '\n'
            dest = '[' + generator.get_register_string(REG_SCRATCH) + ']'

    if type(self.dest.stype) is PointerType:
        desttype = self.dest.stype.pointstotype
    else:
        desttype = self.dest.stype
    typeid = ['b', 'h', None, ''][desttype.size // 8 - 1]
    if typeid != '' and 'unsigned' in desttype.qual_list:
        typeid = 's' + type

    res += regalloc.gen_spill_load_if_necessary(self.symbol)
    rsrc = regalloc.get_register_for_variable(self.symbol)
    return [res + '\tstr' + typeid + ' ' + rsrc + ', ' + dest + '\n', trail]


def loadstat_codegen(self, regalloc, generator):
    res = ''
    trail = ''
    if self.symbol.alloct == 'reg':
        res += regalloc.gen_spill_load_if_necessary(self.symbol)
        src = '[' + regalloc.get_register_for_variable(self.symbol) + ']'
    else:
        ai = self.symbol.allocinfo
        if type(ai) is LocalSymbolLayout:
            src = '[' + generator.get_register_string(REG_FP) + ', #' + ai.symname + ']'
        else:
            lab, tmp = new_local_const(ai.symname)
            trail += tmp
            res += '\tldr ' + generator.get_register_string(REG_SCRATCH) + ', ' + lab + '\n'
            src = '[' + generator.get_register_string(REG_SCRATCH) + ']'

    if type(self.symbol.stype) is PointerType:
        desttype = self.symbol.stype.pointstotype
    else:
        desttype = self.symbol.stype
    typeid = ['b', 'h', None, ''][desttype.size // 8 - 1]
    if typeid != '' and 'unsigned' in desttype.qual_list:
        typeid = 's' + type

    rdst = regalloc.get_register_for_variable(self.dest)
    res += '\tldr' + typeid + ' ' + rdst + ', ' + src + '\n'
    res += regalloc.gen_spill_store_if_necessary(self.dest)
    return [res, trail]


def loadimm_codegen(self, regalloc, generator):
    rd = regalloc.get_register_for_variable(self.dest)
    val = self.val
    if val >= -256 and val < 256:
        if val < 0:
            rv = -val - 1
            op = 'mvn '
        else:
            rv = val
            op = 'mov '
        res = '\t' + op + rd + ', #' + repr(rv) + '\n'
        trail = ''
    else:
        lab, trail = new_local_const(repr(val))
        res = '\tldr ' + rd + ', ' + lab + '\n'
    return [res + regalloc.gen_spill_store_if_necessary(self.dest), trail]


def unarystat_codegen(self, regalloc, generator):
    res = regalloc.gen_spill_load_if_necessary(self.src)
    rs = regalloc.get_register_for_variable(self.src)
    rd = regalloc.get_register_for_variable(self.dest)
    if self.op == 'plus':
        if rs != rd:
            res += '\tmov ' + rd + ', ' + rs + '\n'
    elif self.op == 'minus':
        res += '\tmvn ' + rd + ', ' + rs + '\n'
        res += '\tadd ' + rd + ', ' + rd + ', #1\n'
    elif self.op == 'odd':
        res += '\tand ' + rd + ', ' + rs + ', #1\n'
    else:
        raise Exception("operation " + repr(self.op) + " unexpected")
    res += regalloc.gen_spill_store_if_necessary(self.dest)
    return res


def generate_code(program, regalloc):
    generator = ArmCodeGenerator()

    res = '\t.text\n'
    res += '\t.arch armv6\n'
    res += '\t.syntax unified\n'
    return res + program.codegen(regalloc, generator)


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
