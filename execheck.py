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
        DOSHeader = {
            "signature": f.read(2).decode(),
            "extraPageSize": f.read(2),
            "numberOfPages": f.read(2),
            "relocations": f.read(2),
            "headerSizeInParagraphs": f.read(2),
            "minimumAllocatedParagraphs": f.read(2),
            "maximumAllocatedParagraphs": f.read(2),
            "initialSSValue": f.read(2),
            "initialRelativeSPValue": f.read(2),
            "checksum": f.read(2),
            "initialRelativeIPValue": f.read(2),
            "initialCSValue": f.read(2),
            "relocationsTablePointer": f.read(2),
            "overlayNumber": f.read(2),
            "reservedWords": f.read(8),
            "oemIdentifier": f.read(2),
            "oemInformation": f.read(2),
            "otherReservedWords": f.read(20),
            "coffHeaderPointer": f.read(4)
        }
        DOSStub = {
            "code": f.read(14),
            "message": f.read(39).decode(),
            "data": f.read(3).decode()
        }
        f.seek(int.from_bytes(DOSHeader["coffHeaderPointer"], byteorder="little"))
        coffHeader = {
            "signature": f.read(4).decode(),
            "architecture": f.read(2),
            "numberOfSections": f.read(2),
            "timeDateStamp": f.read(4),
            "pointerToSymbolTable": f.read(4),
            "numberOfSymbols": f.read(4),
            "sizeOfOptionalHeader": f.read(2),
        }
        array = f.read(2)
        byte1 = "{0:08b}".format(array[0])
        byte2 = "{0:08b}".format(array[1])
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

        if int.from_bytes(coffHeader["sizeOfOptionalHeader"], byteorder="little") > 0:
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
