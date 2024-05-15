#!/usr/bin/env python3

"""The main function of the compiler, AKA the compiler driver"""

import lexer
import parser
from support import *
from datalayout import *
from cfg import *
from regalloc import *
from codegen import *


def compile_program(text):
    lex = lexer.Lexer(text)
    pars = parser.Parser(lex)
    res = pars.program()
    print('\n', res, '\n')

    res.navigate(print_stat_list)

    node_list = get_node_list(res)
    for n in node_list:
        print(type(n), id(n), '->', type(n.parent), id(n.parent))
    print('\nTotal nodes in IR:', len(node_list), '\n')

    res.navigate(lowering)

    node_list = get_node_list(res)
    print('\n', res, '\n')
    for n in node_list:
        print(type(n), id(n))
        try:
            n.flatten()
        except Exception:
            pass
    # res.navigate(flattening)
    print('\n', res, '\n')

    print_dotty(res, "log.dot")

    print("\n\nDATALAYOUT\n\n")
    perform_data_layout(res)
    print('\n', res, '\n')

    cfg = CFG(res)
    cfg.liveness()
    cfg.print_liveness()
    cfg.print_cfg_to_dot("cfg.dot")

    print("\n\nREGALLOC\n\n")

    # by changing this line, we limit the number of available registers
    ra = LinearScanRegisterAllocator(cfg, 11)
    reg_alloc = ra()
    print(reg_alloc)

    print("\n\nCODEGEN\n\n")
    code = generate_code(res, reg_alloc)
    print(code)

    return code


import sys


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("error: you must provide at least a source file")
        exit(1)

    for source_file in sys.argv[1:]:
        output_file = source_file.split('/')[-1].split('.')[0] + '.s'

        with open(source_file, 'r') as f:
            source = f.read()
            code   = compile_program(source)

        with open(output_file, 'w') as f:
            f.write(code)
