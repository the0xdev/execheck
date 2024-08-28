#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2024 Imran Mustafa <imran@imranmustafa.net>
#
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
from pathlib import Path
import subprocess
import pprint

def execheck(file: Path) -> dict:
    with open(file, "rb") as f:
        readstr = lambda bytes : f.read(bytes).decode()
        readhex = lambda bytes : int.from_bytes(f.read(bytes), byteorder="little")
        DOSHeader = {
            "signature": readstr(2),
            "extraPageSize": readhex(2),
            "numberOfPages": readhex(2),
            "relocations": readhex(2),
            "headerSizeInParagraphs": readhex(2),
            "minimumAllocatedParagraphs": readhex(2),
            "maximumAllocatedParagraphs": readhex(2),
            "initialSSValue": readhex(2),
            "initialRelativeSPValue": readhex(2),
            "checksum": readhex(2),
            "initialRelativeIPValue": readhex(2),
            "initialCSValue": readhex(2),
            "relocationsTablePointer": readhex(2),
            "overlayNumber": readhex(2),
            "reservedWords": readhex(8),
            "oemIdentifier": readhex(2),
            "oemInformation": readhex(2),
            "otherReservedWords": readhex(20),
            "coffHeaderPointer": readhex(4)
        }
        DOSStub = {
            "code": readhex(14),
            "message": readstr(39),
            "data": readstr(3)
        }
        f.seek(DOSHeader["coffHeaderPointer"])
        coffHeader = {
            "signature": readstr(4),
            "architecture": readhex(2),
            "numberOfSections": readhex(2),
            "timeDateStamp": readhex(4),
            "pointerToSymbolTable": readhex(4),
            "numberOfSymbols": readhex(4),
            "sizeOfOptionalHeader": readhex(2),
        }
        array = f.read(2)
        byte_bit_bool = lambda arr: list(map(lambda c : True if c == "1" else False, "{0:08b}".format(arr)))
        byte1 = byte_bit_bool(array[0])
        byte2 = byte_bit_bool(array[1])
        Characteristics = {
            "baseRelocationsStripped": byte1[7],
            "executableImage": byte1[6],
            "lineNumbersStripped": byte1[5],
            "symbolsStripped": byte1[4],
            "aggressivelyTrimWorkingSet": byte1[3],
            "largeAddressAware": byte1[2],
            "bytesReversedLo": byte1[0],
            "machine32Bit": byte2[7],
            "debugInfoStripped": byte2[6],
            "removableRunFromSwap": byte2[5],
            "netRunFromSwap": byte2[4],
            "systemFile": byte2[3],
            "dll": byte2[2],
            "uniprocessorMachineOnly": byte2[1],
            "bytesReversedHi": byte2[0] 
        }
        coffHeader["Characteristics"] = Characteristics

        if coffHeader["sizeOfOptionalHeader"] > 0:
            optionalHeader = {
            
            }
            coffHeader["optionalHeader"] = optionalHeader
        
    return {
        "PEHeader": {
            "DOSheader": DOSHeader,
            "DOSStub": DOSStub,
        },
        "coffHeader": coffHeader
    }

def wincheck(file: Path):
    func_call = ['file', '-i', file]
    
    exere = f"{file}: application/vnd.microsoft.portable-executable; charset=binary\n"

    process = subprocess.Popen(func_call, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    response, err = process.communicate()
    
    if not err == b'':
        raise OSError(err.decode())

    response = response.decode()
    print(response, end="")

    if exere == response:
        print("checking exe...")
        pprint.pp(execheck(file))
    else:
        print(f"{file} is not an exe")

if __name__ == "__main__":
    if (argc := len(sys.argv)) < 2:
        raise ValueError(f"expected 1 or more arguments got {argc - 1}")
    for file in map(Path, sys.argv[1:]):
        if file.is_file():
            wincheck(file)
        else:
            print(f"{file} is not a file.")
