def get_tokens(line):
    x = line.strip().split(" ")
    tokens = [token for token in x if token != ""]
    if "C'" in line :
        if len(tokens)>4:
            tokens[3]+=" "+tokens[4]
            return  tokens[:-1]
    return tokens


def get_binary_from_opcode(opcode):
    x = int(opcode, 16)
    y = x >> 2
    return f"{y:06b}"


def calculate_displacement(pc, target_address):
    disp = target_address - pc
    return f"{disp:03x}"


def convert_from_binary_to_hexa(str):
    x = int(str, 2)
    return f"{x:03x}"


def get_value_of_base(lines, symtab):
    for line in lines:
        tokens = get_tokens(line)
        if tokens[1].lower() == 'base':
            return int(symtab[tokens[2]]["address"], 16)
    return 0


def convert_decimal_to_hexa(x):
    y = int(x)
    return f"{y:03x}"

def line_has_no_object(line):
    x=["base","ltorg","start","end","resw","resb"]
    for s in x:
        if s in line.lower():
            return  True
    return False

def pad_to_six_chars(input_string):

    return input_string + 'X' * (6 - len(input_string)) if len(input_string) < 6 else input_string
