#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2024 Imran Mustafa <imran@imranmustafa.net>
#
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
from pathlib import Path
from enum import Enum
import time
import subprocess
import pprint

class Architecture(Enum):
	Unknown = "0x00"
	ALPHAAXPOld = "0x183"
	ALPHAAXP = "0x184"
	ALPHAAXP64Bit = "0x284"
	AM33 = "0x1d3"
	AMD64 = "0x8664"
	ARM = "0x1d0"
	ARM64 = "0xaa64"
	ARMNT = "0x1c4"
	CLRPureMSIL = "0xc0ee"
	EBC = "0xebc"
	I386 = "0x14c"
	I860 = "0x14d"
	IA64 = "0x200"
	LOONGARCH32 = "0x6232"
	LOONGARCH64 = "0x6264"
	M32R = "0x9041"
	MIPS16 = "0x266"
	MIPSFPU = "0x366"
	MIPSFPU16 = "0x466"
	MOTOROLA68000 = "0x268"
	POWERPC = "0x1f0"
	POWERPCFP = "0x1f1"
	POWERPC64 = "0x1f2"
	R3000 = "0x162"
	R4000 = "0x166"
	R10000 = "0x168"
	RISCV32 = "0x5032"
	RISCV64 = "0x5064"
	RISCV128 = "0x5128"
	SH3 = "0x1a2"
	SH3DSP = "0x1a3"
	SH4 = "0x1a6"
	SH5 = "0x1a8"
	THUMB = "0x1c2"
	WCEMIPSV2 = "0x169"

def execheck(file: Path) -> dict:
    with open(file, "rb") as f:
        readstr = lambda bytes : f.read(bytes).decode()
        readint = lambda bytes : int.from_bytes(f.read(bytes), byteorder="little")
        DOSHeader = {
            "signature": readstr(2),
            "extraPageSize": readint(2),
            "numberOfPages": readint(2),
            "relocations": readint(2),
            "headerSizeInParagraphs": readint(2),
            "minimumAllocatedParagraphs": readint(2),
            "maximumAllocatedParagraphs": readint(2),
            "initialSSValue": readint(2),
            "initialRelativeSPValue": readint(2),
            "checksum": readint(2),
            "initialRelativeIPValue": readint(2),
            "initialCSValue": readint(2),
            "relocationsTablePointer": readint(2),
            "overlayNumber": readint(2),
            "reservedWords": readint(8),
            "oemIdentifier": readint(2),
            "oemInformation": readint(2),
            "otherReservedWords": readint(20),
            "coffHeaderPointer": readint(4)
        }
        DOSStub = {
            "code": readint(14),
            "message": readstr(39),
            "data": readstr(3)
        }
        f.seek(DOSHeader["coffHeaderPointer"])
        coffHeader = {
            "signature": readstr(4),
            "architecture": Architecture(hex(readint(2))).name,
            "numberOfSections": readint(2),
            "timeDateStamp": time.ctime(readint(4)),
            "pointerToSymbolTable": readint(4),
            "numberOfSymbols": readint(4),
            "sizeOfOptionalHeader": readint(2),
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
