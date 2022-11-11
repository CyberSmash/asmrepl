from typing import Tuple, List

from unicorn import *
from prompt_toolkit import prompt
import argparse
from keystone import *
#from keystone.x86_const import *
from unicorn.x86_const import *
from prompt_toolkit.history import FileHistory
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.styles import style_from_pygments_cls
from pygments.lexers.asm import NasmLexer
from pygments.styles import get_all_styles, get_style_by_name
from pygments.styles.gruvbox import GruvboxDarkStyle
from command_router import get_command_parser
from hurry.filesize import size, si
from rich.table import Table
from rich.console import Console

#print(list(get_all_styles()))

ADDRESS = 0x1000000

mu = Uc(UC_ARCH_X86, UC_MODE_64)
ks = Ks(KS_ARCH_X86, KS_MODE_64)

register_enum_names = [item for item in dir(unicorn.x86_const) if item.startswith("UC_X86_REG_")]
basic_registers = {"rax": UC_X86_REG_RAX, "rbx": UC_X86_REG_RBX, "rcx": UC_X86_REG_RCX,
                 "rdx": UC_X86_REG_RDX, "rdi": UC_X86_REG_RDI, "rsi": UC_X86_REG_RSI,
                 "rip": UC_X86_REG_RIP, "rsp": UC_X86_REG_RSP}
all_registers = {}


memory_maps: List[Tuple] = []

def dorh(val: str):
    if val.startswith("0x"):
        return int(val, 16)
    else:
        return int(val, 10)

def initialize_registers():
    for register_enum_name in register_enum_names:
        pass


def print_registers(mu, ks, user_data):
    for name, reg_enum in basic_registers.items():
        val = mu.reg_read(reg_enum)
        print(f"{name} = {val:02X}")


def print_register(mu: unicorn.Uc, ks, args):
    user_register_name: str
    for user_register_name in args.register_name:
        register_name = f"UC_X86_REG_{user_register_name.upper()}"
        register_val = getattr(unicorn.x86_const, register_name, None)
        if register_val is None:
            print(f"Register {register_name} not defined.")
            return
        val = mu.reg_read(register_val)
        print(f"{user_register_name.lower()} = {val:02X}")


def is_command(command):
    command_split = command.split()
    return command_split[0] in command_router


def route_command(command):
    global mu
    global ks
    command_split = command.split()
    primary_command = command_split[0]
    if primary_command in command_router.keys():
        command_router[primary_command](command_split)


def print_memory(uc, ks, args):
    try:
        data = mu.mem_read(int(args.address, 16), int(args.num_bytes, 16))
        for idx, b in enumerate(data):
            if idx % 16 == 0 and idx != 0:
                print("")
            print(f"{b:02X} ", end="")
        print("")
    except Exception as ex:
        print(f"{ex} and it's type is {type(ex)}")


def print_command(args):
    if args.print_type == 'registers':
        if len(args.register_name) == 1 and (args.register_name[0] == 'all' or args.register_name[0] == 'basic'):
            print_registers(mu, ks, None)
        else:
            print_register(mu, ks, args)

    if args.print_type == 'memory':
        print_memory(mu, ks, args)

    if args.print_type == 'memory':
        pass


def reset_command(user_data):
    global mu
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(ADDRESS, 2*1024*1024)


def help_command(user_data):
    print("Help ...")

def memory_command(args):
    global memory_maps
    if args.memory_action == 'show':
        table = Table(title='Memory Maps')
        table.add_column("Begin Addr.")
        table.add_column("End Addr.")
        table.add_column("Size")
        for address, mem_size in memory_maps:
            table.add_row(f"{address:02X}", f"{address+mem_size:02X}", size(mem_size))

        console = Console()
        console.print(table)
    if args.memory_action == 'map':
        addr = dorh(args.base_address)
        mem_size = dorh(args.memory_size)
        mu.mem_map(addr, mem_size)
        memory_maps.append((addr, mem_size))

command_router = {
    "print": print_command,
    "reset": reset_command,
    "help": help_command,
}

CommandCompleter = NestedCompleter.from_nested_dict({
    '/print': {
        'registers': None,
        'memory': None,
    },
    '/map-memory': None,
    '/reset': None,
    '/help': None,
})

def main():
    global memory_maps
    mu.mem_map(ADDRESS, 2*1024*1024)
    memory_maps.append((ADDRESS, 2*1024*1024))
    our_style = style_from_pygments_cls(GruvboxDarkStyle)
    parser = get_command_parser()
    while 1:
        command = prompt(">>> ", history=FileHistory('.history.txt'),
                         completer=CommandCompleter,
                         lexer=PygmentsLexer(NasmLexer),
                         style=our_style)
        if command == 'quit':
            break

        if command.startswith('/'):
            command = command[1:]
            try:
                args = parser.parse_args(command.split())
                print(args)

            except SystemExit:
                pass
                # print("Error with command.")
            if args.command == 'help':
                parser.print_help()
                subparsers_actions = [action for action in parser._actions if
                                      isinstance(action, argparse._SubParsersAction)]
                for subparsers_actions in subparsers_actions:
                    for choice, subparser in subparsers_actions.choices.items():
                        subparser.print_help()

            if args.command == 'print':
                print_command(args)

            if args.command == 'memory':
                memory_command(args)
            continue
        else:
            try:
                encoding, _ = ks.asm(command)
            except KsError as e:
                print(e)
                continue


        mu.mem_write(ADDRESS, bytes(encoding))
        mu.emu_start(ADDRESS, ADDRESS+len(encoding))

if __name__ == '__main__':
    main()
