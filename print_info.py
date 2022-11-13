from typing import List
import typer
from utils import strtoint
from unicorn_helpers import basic_registers
import unicorn.x86_const

app = typer.Typer()


@app.command()
def memory(ctx: typer.Context, address: str, num_bytes: str):
    mu = ctx.obj['mu']
    address = strtoint(address)
    num_bytes = strtoint(num_bytes)

    try:
        data = mu.mem_read(address, num_bytes)
        for idx, b in enumerate(data):
            if idx % 16 == 0 and idx != 0:
                print("")
            print(f"{b:02X} ", end="")
        print("")
    except Exception as ex:
        print(f"{ex} and it's type is {type(ex)}")

@app.command()
def register(ctx: typer.Context, register_names: List[str]):
    mu = ctx.obj['mu']

    for register_name in register_names:
        unicorn_reg_name = f"UC_X86_REG_{register_name.upper()}"
        register_val = getattr(unicorn.x86_const, unicorn_reg_name, None)

        if register_val is None:
            print(f"Register {register_name} not defined.")
            return

        val = mu.reg_read(register_val)
        print(f"{register_name.lower()} = {val:02X}")


@app.command()
def registers(ctx: typer.Context):
    mu = ctx.obj['mu']
    for name, reg_enum in basic_registers.items():
        val = mu.reg_read(reg_enum)
        print(f"{name} = {val:02X}")