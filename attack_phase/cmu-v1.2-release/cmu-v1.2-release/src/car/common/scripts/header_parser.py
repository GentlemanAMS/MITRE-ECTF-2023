from typing import Dict

# Given the path to a C header file,
# parses all of the `#define` macros.
# Defines that don't have a value are ignored.
# Includes are ignored.
def parse_header(path: str) -> Dict[str, int]:
    with open(path, "r") as f:
        data = f.read()
    
    return parse_header_content(data)


# Given the content of a C header file,
# parses all of the `#define` macros.
# Defines that don't have a value are ignored.
# Includes are ignored.
def parse_header_content(s: str) -> Dict[str, int]:
    lines = s.splitlines()

    result = dict()

    for line in lines:
        if not line.startswith('#define '):
            continue

        parts = line.split()
        if len(parts) == 2:
            # No value
            continue
            
        _, name, value, *_ = parts 
        if value.startswith('(') and value.endswith(')'):
            value = value[1:-1]

        if value.startswith('0x'):
            value = int(value[2:], base=16)
        else:
            value = int(value)

        result[name] = value


    return result