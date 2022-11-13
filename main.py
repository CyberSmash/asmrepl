from typing import Tuple, List

from unicorn import *
from prompt_toolkit import prompt
from keystone import *
from prompt_toolkit.history import FileHistory
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.styles import style_from_pygments_cls
from pygments.lexers.asm import NasmLexer
from pygments.styles import get_all_styles, get_style_by_name
from pygments.styles.gruvbox import GruvboxDarkStyle
import typer
import print_info
import memory_map
import traceback

ADDRESS = 0x1000000
mu = Uc(UC_ARCH_X86, UC_MODE_64)
ks = Ks(KS_ARCH_X86, KS_MODE_64)
memory_maps: List[Tuple] = []

app = typer.Typer(context_settings={'obj': {'mu': mu, 'memory_map': memory_maps}})
app.add_typer(print_info.app, name="print")
app.add_typer(memory_map.app, name="memory")
register_enum_names = [item for item in dir(unicorn.x86_const) if item.startswith("UC_X86_REG_")]

all_registers = {}


CommandCompleter = NestedCompleter.from_nested_dict({
    '/print': {
        'register': None,
        'registers': None,
        'memory': None,
    },
    '/memory': {
        '/map': None,
        '/show': None,
    },
    '/reset': None,
    '/quit': None,
})

def main():
    global mu
    global memory_maps

    # TODO: Fix this, make it configurable.
    mu.mem_map(ADDRESS, 2*1024*1024)
    memory_maps.append((ADDRESS, 2*1024*1024))
    our_style = style_from_pygments_cls(GruvboxDarkStyle)

    while 1:
        command = prompt(">>> ", history=FileHistory('.history.txt'),
                         completer=CommandCompleter,
                         lexer=PygmentsLexer(NasmLexer),
                         style=our_style)
        if command == '/quit':
            break
        if command == '/reset':
            # TODO: Fix this, mu should probably not be a global, and easier to deal with.
            # Sadly, this is probably the best place to handle this as we
            # have access to the global.

            # TODO: This code is repeat, fix it.

            mu = Uc(UC_ARCH_X86, UC_MODE_64)
            mu.mem_map(ADDRESS, 2 * 1024 * 1024)
            memory_maps.append((ADDRESS, 2 * 1024 * 1024))
            continue

        if command.startswith('/'):
            command = command[1:]
            command = command.split()
            print(command)
            try:
                app(command)
            except SystemExit as ex:
                if ex.code != 0:
                    print(f"Error code: {ex.code}")
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
