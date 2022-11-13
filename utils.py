def strtoint(val: str) -> int:
    if val.startswith("0x"):
        return int(val, 16)
    else:
        return int(val, 10)