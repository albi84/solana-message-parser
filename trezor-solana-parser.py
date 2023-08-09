import binascii
import json


with open("input.hex","r") as file:
    data = bytearray.fromhex(file.read())

with open("programs.json", "r") as file:
    programs = json.load(file)


def parseHeader(stream: bytes) -> (int, dict):
    header = dict()

    header["required"] = stream[0]
    header["readonly"] = stream[1]
    header["notrequired"] = stream[2]
    
    return (3, header)

def parseCompactU16(stream: bytes) -> (int, int):
    count = 1
    value = stream[0] & 0x7f

    if stream[0] > 0x7f:
        count += 1
        value = (stream[1] & 0x7f) << 7
        if stream[1] > 0x7f:
            count += 1
            value = (stream[2] & 0x7f) << 14

    return (count, value)

def parsePublickKey(stream: bytes) -> (int, str):
    # return (32, str(binascii.hexlify(stream[:32])))
    return (32, "".join("{:02x}".format(x) for x in stream[:32]))

def parseAccountAddresses(stream: bytes, header: dict) -> (int, dict):
    accounts = dict()
    processed = 0
    offset, accounts["count"] = parseCompactU16(stream)
    processed += offset

    accounts["addresses"] = []
    for x in range(accounts["count"]):
        (offset, account) = parsePublickKey(stream[processed : processed + 32])
        processed += offset
        accounts["addresses"].append(account)

    return (processed, accounts)

def parseRecentBlockhash(stream: bytes) -> (int, str):
    # return (32, str(binascii.hexlify(stream[:32])))
    return (32, "".join("{:02x}".format(x) for x in stream[:32]))

def parseI32(stream: bytes) -> (int, int):
    id = 0
    for x in range(4):
        id += stream[x] << 8 * x
    return (4, id)

def parseInstructionId(stream: bytes) -> (int, int):
    return parseI32(stream)

def parseBasicFamily(stream: bytes, type: str) -> (int, str):
    if type == "u32":
        return (4, "".join("{:02x}".format(x) for x in stream[:4][::-1]))
    elif type == "i32":
        return (4, "".join("{:02x}".format(x) for x in stream[:4][::-1]))
    elif type == "u64":
        return (8, "".join("{:02x}".format(x) for x in stream[:8][::-1]))
    elif type == "i64":
        return (8, "".join("{:02x}".format(x) for x in stream[:8][::-1]))
    elif type == "String":
        padding = 4
        (offset, strlen) = parseI32(stream)
        return (padding + offset + strlen, "".join("{:c}".format(x) for x in stream[padding + offset : padding + offset + strlen]))
    elif type == "Pubkey":
        return (32, "".join("{:02x}".format(x) for x in stream[:32]))
    else:
        # Should not happen
        raise NotImplementedError

def parseStructFamily(stream: bytes, type: str) -> (int, dict):
    # this should raise an error if the struct is not known
    struct = list(filter(lambda x: x["name"] == type, programs["parameters"]))[0]
    fields = list()
    processed = 0

    for field in struct["fields"]:
        (offset, value) = parseParameter(stream[processed:], field["type"])
        processed += offset
        fields.append({"name": field["name"], "type": field["type"], "value": value})
    
    return (processed, fields)

def parseEnumFamily(strem: bytes, type: str) -> (int, dict):
    # return (1, {"int": 0, "text": "Staker"})
    raise NotImplementedError

def parseParameter(stream: bytes, type: str) -> (int, int | str | list | dict):
    paramtype = list(filter(lambda x: x["name"] == type, programs["parameters"]))[0]
    
    if paramtype["family"] == "basic":
        return parseBasicFamily(stream, paramtype["name"])
    elif paramtype["family"] == "struct":
        return parseStructFamily(stream, paramtype["name"])
    elif paramtype["family"] == "enum":
        return parseEnumFamily(stream, paramtype["name"])
    else:
        raise NotImplementedError

def parseInstruction(stream: bytes, knownInstruction: dict) -> (int, dict):
    # create instruction object
    instruction = dict()
    instruction["name"] = knownInstruction["name"]

    # create instruction parameters object
    parameters = list()

    # set parameters
    instruction["parameters"] = parameters

    processed = 0

    # process parameters
    for param in knownInstruction["parameters"]:
        (offset, value) = parseParameter(stream[processed:], param["type"])
        processed += offset
        parameters.append({"name": param["name"], "type": param["type"], "value": value})

    return (processed, instruction)

def parseProgram(stream: bytes, addresses: list, knownPrograms: dict) -> (int, dict):
    processed = 0

    # Get program descriptor from known programs
    # This should throw if the program is not known
    program = list(filter(lambda x: x["id"] == addresses[stream[0]], knownPrograms["programs"]))[0]
    processed += 1

    # Get accounts
    (offset, count) = parseCompactU16(stream[processed:])
    processed += offset
    accounts = []
    for x in range(count):
        accounts.append(addresses[stream[processed + x]])
    processed += count

    # Get instruction data
    (offset, datalen) = parseCompactU16(stream[processed:])
    processed += offset
    instructionData = stream[processed : processed + datalen]
    processed += datalen

    # Get instruction id
    (offset, instructionId) = parseInstructionId(instructionData)

    # Get instruction descriptor from known instructions
    knownInstruction = list(filter(lambda x: x["id"] == instructionId, program["instructions"]))[0]
    (offset, instruction) = parseInstruction(instructionData[offset:], knownInstruction)

    instruction["program"] = "{0} ({1})".format(program["name"], program["id"])

    return (processed, instruction)


def parsePrograms(stream: bytes, addresses: list, knownPrograms: dict) -> (int, dict):
    instructions = dict()
    processed = 0
    offset, instructions["count"] = parseCompactU16(stream)
    processed += offset

    instructions["instructions"] = []
    for x in range(instructions["count"]):
        (offset, instruction) = parseProgram(stream[processed:], addresses, knownPrograms)
        instructions["instructions"].append(instruction)
        processed += offset
    
    return (processed, instructions)

def parseMessage(stream: bytes) -> (int, dict):
    message = dict()
    processed = 0

    (offset, message["header"]) = parseHeader(stream)
    processed += offset
    (offset, message["account_addresses"]) = parseAccountAddresses(stream[processed:], message["header"])
    processed += offset
    (offset, message["recent_blockhash"]) = parseRecentBlockhash(stream[processed:])
    processed += offset
    (offset, message["instructions"]) = parsePrograms(stream[processed:], message["account_addresses"]["addresses"], programs)
    processed += offset

    return (processed, message)

def parseTransaction() -> dict:
    pass

(offset, message) = parseMessage(data)
print(json.dumps(message, indent=4))
