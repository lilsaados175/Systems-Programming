import helper_functions as h
opcodes = {
    "ADD": {"opcode": '18', "format": 3},
    "ADDF": {"opcode": '58', "format": 3},
    "AND": {"opcode": '40', "format": 3},
    "COMP": {"opcode": '28', "format": 3},
    "DIV": {"opcode": '24', "format": 3},
    "J": {"opcode": '3C', "format": 3},
    "JEQ": {"opcode": '30', "format": 3},
    "JGT": {"opcode": '34', "format": 3},
    "JLT": {"opcode": '38', "format": 3},
    "JSUB": {"opcode": '48', "format": 3},
    "LDA": {"opcode": '00', "format": 3},
    "LDB": {"opcode": '68', "format": 3},
    "LDCH": {"opcode": '50', "format": 3},
    "LDF": {"opcode": '70', "format": 3},
    "LDL": {"opcode": '08', "format": 3},
    "LDS": {"opcode": '6C', "format": 3},
    "LDT": {"opcode": '74', "format": 3},
    "LDX": {"opcode": '04', "format": 3},
    "LPS": {"opcode": 'D0', "format": 3},
    "MUL": {"opcode": '20', "format": 3},
    "MULF": {"opcode": '60', "format": 3},
    "SSK": {"opcode": 'EC', "format": 3},
    "OR": {"opcode": '44', "format": 3},
    "RD": {"opcode": 'D8', "format": 3},
    "RSUB": {"opcode": '4C', "format": 3},
    "STA": {"opcode": '0C', "format": 3},
    "STB": {"opcode": '78', "format": 3},
    "STCH": {"opcode": '54', "format": 3},
    "STF": {"opcode": '80', "format": 3},
    "STI": {"opcode": 'D4', "format": 3},
    "STS": {"opcode": '7C', "format": 3},
    "STSW": {"opcode": 'E8', "format": 3},
    "STT": {"opcode": '84', "format": 3},
    "STL": {"opcode": '14', "format": 3},
    "STX": {"opcode": '10', "format": 3},
    "SUB": {"opcode": '1C', "format": 3},
    "SUBF": {"opcode": '5C', "format": 3},
    "TD": {"opcode": 'E0', "format": 3},
    "TIX": {"opcode": '2C', "format": 3},
    "WD": {"opcode": 'DC', "format": 3},
    "CADD": {"opcode": 'BC', "format": 4},  # 4f
    "CSUB": {"opcode": '8C', "format": 4},  # 4f
    "CLOAD": {"opcode": 'E4', "format": 4},  # 4f
    "CSTORE": {"opcode": 'FC', "format": 4},  # 4f
    "CJUMP": {"opcode": 'CC', "format": 4},  # 4f
    "FIX": {"opcode": 'C4', "format": 1},
    "FLOAT": {"opcode": 'C0', "format": 1},
    "HIO": {"opcode": 'F4', "format": 1},
    "NORM": {"opcode": 'C8', "format": 1},
    "SIO": {"opcode": 'F0', "format": 1},
    "TIO": {"opcode": 'F8', "format": 1},
    "ADDR": {"opcode": '90', "format": 2},
    "CLEAR": {"opcode": 'B4', "format": 2},
    "COMPR": {"opcode": 'A0', "format": 2},
    "DIVR": {"opcode": '9C', "format": 2},
    "DIVF": {"opcode": '64', "format": 3},
    "MULR": {"opcode": '98', "format": 2},
    "RMO": {"opcode": 'AC', "format": 2},
    "SHIFTL": {"opcode": 'A4', "format": 2},
    "SHIFTR": {"opcode": 'A8', "format": 2},
    "SUBR": {"opcode": '94', "format": 2},
    "SVC": {"opcode": 'B0', "format": 2},
    "TIXR": {"opcode": 'B8', "format": 2}
}
all_registers = {"A": '0', "X": '1', "L": '2', "B": '3', "S": '4', "T": '5', "F": '6'}
symbol_table = {}
literal_table = {}
blocknames=["Default","DEFAULTB","CDATA","CBLKS"]

blocks = {"Default": {"start": 0, "location_counter": 0, "length": 0}}

start_address = 0
program_name = ""
program_length = 0
errors=False

def pass1():
    global start_address
    global program_name
    global program_length
    global errors
    f = open("source.txt", 'r')
    f2 = open("out_pass_1.txt", 'w')
    f3 = open("symbol_Table.txt", 'w')
    lines = f.readlines()
    block = "Default"
    for line in lines:
        if line.strip().startswith("."):
            continue
        tokens = line.strip().split()
        location_counter = blocks[block]["location_counter"]
        if len(tokens) == 3:
            operation = tokens[1]
            operand = tokens[2]
            if tokens[1].lower() == "start":
                start_address = int(tokens[2], 16)
                program_name = tokens[0]
                location_counter = int(tokens[2], 16)
                blocks["Default"]["start"] = location_counter
                blocks["Default"]["location_counter"] = location_counter
                f2.write(f"{location_counter:04x}".upper() + " " + line.strip() + "\n")
                continue
            symbol_table[tokens[0]] = {"block": block, "address": hex(location_counter)}
        elif len(tokens) == 2:
            operation = tokens[0]
            operand = tokens[1]
            if operation.lower() == "use":
                block = operand
                if block not in blocknames:
                    print("block "+block+" is not defined")
                    errors=True
                    break
        elif len(tokens) == 1:
            operation = tokens[0]
            if operation.lower() == "use":
                block = "Default"
        if blocks.get(block) is None:
            blocks[block] = {"start": start_address, "location_counter": start_address,
                             "length": 0}
        location_counter = blocks[block]["location_counter"]
        f2.write(f"{location_counter:04x}".upper() + " " + line.strip() + "\n")
        if operand.lower().startswith("=x"):
            if operand not in literal_table:
                literal_table[operand] = {"address": None, "length": (len(operand) - 4) // 2, "value": operand[3:-1],"block":block}
        elif operand.lower().startswith("=c"):
            stri = operand[3:-1]
            lit_hexa = ""
            for ch in stri:
                lit_hexa += f"{ord(ch):02x}"
                if operand not in literal_table:
                    literal_table[operand] = {"address": None, "length": (len(operand) - 4), "value": lit_hexa,"block":block}
        if operation.startswith("+"):
            location_counter += 4
        elif opcodes.get(operation) is not None:
            location_counter += opcodes[operation]["format"]
        elif operation.lower() == "word":
            location_counter += 3
        elif operation.lower() == "byte":
            if tokens[2].startswith("X"):
                location_counter += (len(tokens[2]) - 3) // 2  # X'12AB' 2 bytes
            else:
                location_counter += (len(tokens[2]) - 3)  # C'Hello' 5 bytes
        elif operation.lower() == "resw":
            location_counter += int(tokens[2]) * 3
        elif operation.lower() == "resb":
            location_counter += int(tokens[2])
        elif operation.lower() == "end" or operation.lower() == "ltorg":
            for x in literal_table:
                if literal_table[x]["address"] is None:
                    literal_table[x]["address"] = location_counter
                    literal_table[x]["block"]=block
                    f2.write(f"{location_counter:04x}".upper()+ " * " + x + "\n")
                    location_counter = location_counter + literal_table[x]["length"]
        blocks[block]["location_counter"] = location_counter
    if not errors:
        for b in blocks:
            blocks[b]["length"] = blocks[b]["location_counter"] - blocks[b]["start"]
        start_address_def = start_address
        length_def = blocks["Default"]["length"]
        for b in blocks:
            program_length += blocks[b]["length"]
            if b != "Default":
                blocks[b]["start"] = start_address_def + length_def
                start_address_def = start_address_def + length_def
                length_def = blocks[b]["length"]
    f2.close()
    f3.close()
    #print(symbol_table)
    #print(literal_table)


def pass2():
    global errors
    if errors:
        return
    f = open("out_pass_1.txt", 'r')
    f4 = open("out_pass_2.txt", 'w')
    lines = f.readlines()
    loc_ctr = 0
    block = "Default"
    for line in lines:
        objectcode = ""
        tokens = h.get_tokens(line)
        if len(tokens) == 4:
            operation = tokens[2]
            operand = tokens[3]  # LOOP ADDR A,X
            if tokens[2].lower() == "start":  # No object code
                f4.write(f"{line.strip()}\n")
                continue
        elif len(tokens) == 2:
            operation = tokens[1]
            if operation.lower() == "use":
                block = "Default"
        elif len(tokens) == 3:
            operation = tokens[1]
            operand = tokens[2]  # ADDR A,x
            if operation.lower() == "use":
                block = operand
        if operation.startswith("+"):
            opcode = opcodes[operation[1:]]["opcode"]
            # format 4 object code
        if opcodes.get(operation) != None:
            format = opcodes[operation]["format"]
            opcode = opcodes[operation]["opcode"]
            if format == 1:
                objectcode = opcode
            elif format == 2:
                objectcode += opcode
                registers_str = operand.split(",")  # regs=['A','x']
                if len(registers_str) == 1:
                    objectcode += all_registers[registers_str[0]] + '0'
                if len(registers_str) > 1:
                    objectcode += all_registers[registers_str[0]]
                    objectcode += all_registers[registers_str[1]]
            elif format == 3:
                n, x, i, b, p = '0', '0', '0', '0', '0'
                if operation.lower() == 'rsub':
                    objectcode = '4f0000'
                    f4.write(f"{line.strip()} {objectcode}\n")
                    continue
                if operand.startswith("@"):
                    n = '1'
                elif operand.startswith("#"):
                    i = '1'
                else:
                    n, i = '1', '1'
                if operand.lower().endswith(",x"):
                    operand = operand[:-2]
                    x = '1'
                else:
                    x = '0'
                opcode_bin = h.get_binary_from_opcode(opcode)
                if operand.startswith("="):
                    target = literal_table[operand]["address"]
                    target = target - start_address + blocks[literal_table[operand]["block"]]["start"]
                    pc = int(tokens[0], 16) + 3
                    pc = pc - start_address + blocks[block]["start"]
                    disp = target - pc
                    if -2048 < disp < 2047:
                        b = '0'
                        p = '1'
                        # print(f"  disp: {hex(disp)}")
                        disp = h.calculate_displacement(pc, target)
                    else:
                        b = '1'
                        p = '0'
                        base = h.get_value_of_base(lines, symbol_table)
                        print(f"  Base: {hex(base)}")
                        base = base - start_address + blocks[block]["start"]
                        disp = h.calculate_displacement(base, target)
                    opcode_bin = opcode_bin + n + i + x + b + p + "0"
                    opcode_hexa = h.convert_from_binary_to_hexa(opcode_bin)
                    objectcode = opcode_hexa + disp
                if operand.startswith("@"):
                    operand = operand[1:]
                if operand.startswith("#"):
                    operand = operand[1:]
                    if operand.isdigit():
                        disp = h.convert_decimal_to_hexa(operand)
                        opcode_bin = opcode_bin + n + i + x + b + p + "0"
                        opcode_hexa = h.convert_from_binary_to_hexa(opcode_bin)
                        objectcode = opcode_hexa + disp
                        f4.write(line.strip() + " " + objectcode.upper() + "\n")
                        continue
                pc = int(tokens[0], 16) + 3
                pc = pc - start_address + blocks[block]["start"]
                if symbol_table.get(operand) is not None:
                    target = int(symbol_table[operand]["address"], 16)
                    target = target - start_address + blocks[symbol_table[operand]["block"]]["start"]
                    disp = target - pc
                    if -2048 <= disp <= 2047:
                        b = '0'
                        p = '1'
                        disp = h.calculate_displacement(pc, target)
                    else:
                        b = '1'
                        p = '0'
                        base = h.get_value_of_base(lines, symbol_table)
                        base = base - start_address + blocks[block]["start"]

                        disp = h.calculate_displacement(base, target)

                    opcode_bin = opcode_bin + n + i + x + b + p + "0"
                    opcode_hexa = h.convert_from_binary_to_hexa(opcode_bin)
                    objectcode = opcode_hexa + disp
                else:
                    if not operand.startswith("="):
                        print("Error Label "+operand+" is not defined")
                        errors=True
                        break
            elif format == 4:
                registers_str1 =operand.split(",")  # Split Label to get register and memory

                # Extract the register (if any)
                if len(registers_str1) == 3 and registers_str1[0] in all_registers:
                    hamo = all_registers[registers_str1[0]]
                    hamo_bin = f"{int(hamo):04b}"

                    if registers_str1[2] == "Z":
                        condition_flag = "00"  # Zero flag condition
                    elif registers_str1[2] == "N":
                        condition_flag = "01"  # Negative flag condition
                    elif registers_str1[2] == "C":
                        condition_flag = "10"  # Carry flag condition
                    elif registers_str1[2] == "V":
                        condition_flag = "11"  # Overflow flag condition
                    target = int(symbol_table[registers_str1[1]]["address"], 16)
                    target = target - start_address + blocks[symbol_table[registers_str1[1]]["block"]]["start"]
                elif len(registers_str1) == 2:
                    hamo_bin = "0000"
                    if registers_str1[1] == "Z":
                        condition_flag = "00"  # Zero flag condition
                    elif registers_str1[1] == "N":
                        condition_flag = "01"  # Negative flag condition
                    elif registers_str1[1] == "C":
                        condition_flag = "10"  # Carry flag condition
                    elif registers_str1[1] == "V":
                        condition_flag = "11"  # Overflow flag condition
                    target = int(symbol_table[registers_str1[0]]["address"], 16)
                    target = target - start_address + blocks[symbol_table[registers_str1[0]]["block"]]["start"]
                opcode_bin = h.get_binary_from_opcode(opcode)
                opcode_bin = opcode_bin + hamo_bin + condition_flag
                opcode_hexa = h.convert_from_binary_to_hexa(opcode_bin)
                target_hex = f"{target:05X}"  # Ensure address is 20 bits in hexadecimal

                # Combine the components: opcode, register, condition_flag, and address
                objectcode = opcode_hexa + target_hex
        elif operation.startswith("+"):
            n, x, i, = '0', '0', '0'
            if operand.startswith("@"):
                n = '1'
            elif operand.startswith("#"):
                i = '1'
            else:
                n, i = '1', '1'
            if operand.lower().endswith(",x"):
                operand = operand[:-2]
                x = '1'
            else:
                x = '0'
            if operand.startswith("#"):
                operand = operand[1:]
            if symbol_table.get(operand) is None:
                print("Error Label "+operand+  "is not defined")
                errors=True
                break
            opcode_bin = h.get_binary_from_opcode(opcode)
            opcode_bin = opcode_bin + n + i + x + "001"

            opcode_hexa = h.convert_from_binary_to_hexa(opcode_bin)
            target = int(symbol_table[operand]["address"], 16)
            # target = target - start_address + blocks[block]["start"]
            target = target - start_address + blocks[symbol_table[operand]["block"]]["start"]

            target_hex = f"{target:05x}"
            objectcode = opcode_hexa + target_hex
        else:
            if operation.lower() == "*":
                objectcode=literal_table[operand]["value"]
            elif operation.lower() == "word":
                objectcode = f"{int(operand):06X}"
            elif operation.lower() == "byte":
                if operand.startswith("C'") and operand.endswith("'"):
                    chars = operand[2:-1]  # Strip the C' and ending quote
                    ascii = [ord(c) for c in chars]  # Convert chars to ASCII
                    objectcode = (''.join(f"{code:02X}" for code in ascii))  # Convert to hex string
                elif operand.startswith("X'") and operand.endswith("'"):
                    hex_value = operand[2:-1]  # Strip X' and ending quote
                    objectcode = hex_value.upper()  # Return the hex value directly
        f4.write(line.strip() + " " + objectcode.upper() + "\n")
    f4.close()


def generate_htme_records():
    if errors:
        return

    text_records = []
    modification_records = []
    current_t_start = None
    current_t_object_code = ""
    current_t_size = 0
    current_block_start = 0  # Default block start address

    with open("out_pass_2.txt", "r") as file:
        for line in file:
            line = line.strip()

            # Skip empty lines or lines with no object code
            if not line or h.line_has_no_object(line):
                continue

            # Split the line into parts
            parts = line.split()
            if len(parts) < 2:  # Ensure there are at least two parts
                print(f"Skipping malformed line: {line}")
                continue

            # Handle "use" directive: Start a new T record and adjust block address
            if "use" in line.lower():
                if len(parts) == 3:  # Ensure there's a block name after "use"
                    block_name = parts[2]
                    # Set the block's start address dynamically (example logic)
                    current_block_start = blocks.get(block_name, {}).get("start", 0)
                else:
                    current_block_start = 0  # Reset to default if no block name is provided

                # Finalize the current T record
                if current_t_object_code:
                    text_records.append(
                        f"T{current_t_start:06X}{len(current_t_object_code) // 2:02X}{current_t_object_code}"
                    )
                # Reset T record variables
                current_t_start = None
                current_t_object_code = ""
                current_t_size = 0
                continue

            # Attempt to convert parts[0] to a hexadecimal address
            try:
                address = int(parts[0], 16)  # Convert the first part to hex
            except ValueError:
                print(f"Invalid hexadecimal value in line: {line}")
                continue

            # Add the original block address to the calculated address
            address = address - start_address + current_block_start

            # Extract object code (last part of the line)
            object_code = parts[-1]
            if len(object_code) == 8:  # Handle format 4 instructions
                modification_records.append(f"M{address + 1:06X}05")

            # Start a new T record if necessary
            if current_t_start is None:
                current_t_start = address

            # Check if the current T record is full
            if current_t_size + len(object_code) > 60:  # 60 hex characters = 30 bytes
                text_records.append(
                    f"T{current_t_start:06X}{len(current_t_object_code) // 2:02X}{current_t_object_code}"
                ) 
                current_t_start = address
                current_t_object_code = object_code
                current_t_size = len(object_code)
            else:
                current_t_object_code += object_code
                current_t_size += len(object_code)

    # Finalize the last T record
    if current_t_object_code:
        text_records.append(
            f"T{current_t_start:06X}{len(current_t_object_code) // 2:02X}{current_t_object_code}"
        )

    # Create Header and End Records
    hamo_progname = h.pad_to_six_chars(program_name)

    header_record = f"H{hamo_progname}{start_address:06X}{program_length:06X}"
    end_record = f"E{start_address:06X}"

    # Write all records to the HTME.txt file
    with open("HTME.txt", "w") as output_file:
        output_file.write(header_record + "\n")
        for record in text_records:
            output_file.write(record + "\n")
        for record in modification_records:
            output_file.write(record + "\n")
        output_file.write(end_record + "\n")
def print_blocks():
    for block in blocks:
        print(f"block :{block} Address:{blocks[block]['start']:04X} Length:{blocks[block]['length']:04X}")
def print_symTab():
    file=open("symbol_Table.txt","w")
    for sym in symbol_table:
        address=int(symbol_table[sym]["address"],16)
        address=address-start_address+blocks[symbol_table[sym]["block"]]["start"]
        file.write(sym+" "+f"{address:04x}\n".upper())
    for lit in literal_table:
        address=literal_table[lit]["address"]
        address=address-start_address+blocks[literal_table[lit]["block"]]["start"]
        file.write(lit+" "+f"{address:04x}\n".upper())

    file.close()
def assemble():
    pass1()
    print_blocks()
    pass2()
    generate_htme_records()
    print_symTab()
assemble()
