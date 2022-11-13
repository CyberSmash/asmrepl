import typer
from rich.console import Console
from hurry.filesize import size, si
from rich.table import Table
from utils import strtoint
app = typer.Typer()


@app.command()
def show(ctx: typer.Context):
    memory_map = ctx.obj['memory_map']
    table = Table(title='Memory Maps')
    table.add_column("Begin Addr.")
    table.add_column("End Addr.")
    table.add_column("Size")
    for address, mem_size in memory_map:
        table.add_row(f"{address:02X}", f"{address + mem_size:02X}", size(mem_size))

    console = Console()
    console.print(table)


@app.command()
def map(ctx: typer.Context, base_address: str, memory_size: str):
    mu = ctx.obj['mu']
    memory_map = ctx.obj['memory_map']
    addr = strtoint(base_address)
    mem_size = strtoint(memory_size)
    mu.mem_map(addr, mem_size)
    memory_map.append((addr, mem_size))