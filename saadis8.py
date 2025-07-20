#!/usr/bin/env python3

"""Disassembler for MC6808 microprocessor."""

# BSD Zero Clause License
#
# Copyright (c) 2025 Scott A. Anderson
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

import argparse
from collections.abc import Sequence
from dataclasses import dataclass, field
import os
import sys

# This code has been written with the hope that it can be easily adapted to
# work with other 8-bit von Neumann architecture CPUs.
#
# The representations of devices is very, very minimal because producing
# disassembled code doesn't require more.
#
# In this code, a "CPU" object fetches opcodes from a "ROM" object with the
# mapping from a CPU address to an address in a ROM provided by a "MemoryMap"
# object.  Trying to fetch an opcode from a non-"ROM" "MemoryDevice" object
# results in an exception being raised.

# SAATODO: Do the actual disassembly (target crasm)
# SAATODO: Figure out module/package

VERSION='0.01'

def progname() -> str:
    """
    Return the name of this program.
    """
    return os.path.basename(__file__)

def parse_args() -> argparse.Namespace:
    """
    Parse the command line arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__, prog=progname(),
                                     add_help=False)
    parser.add_argument('-h', '--help',
                        help='display this help and exit',
                        action='help')
    parser.add_argument('-V', '--version',
                        help='output version information and exit',
                        action='version', version='%(prog)s v' + VERSION)
    parser.add_argument('--notify-unfollowed',
                        help='print operands that are not followed to stderr',
                        action='store_true')
    parser.add_argument('--notify-vectors',
                        help='print vectors being processed to stderr',
                        action='store_true')
    parser.add_argument('rom_file', metavar='ROM_FILE',
                        help='file containing the ROM image')
    args = parser.parse_args()

    return args

class Disassem8Error(Exception):
    """
    Base class for all of our possible exceptions.
    """

class LocationAccessError(Disassem8Error):
    """
    Exception raised when an attempt is made to fetch an opcode from non-ROM.
    """
    def __init__(self, name: str, offset: int):
        self.name = name
        self.offset = offset
        self.message = (f'Attempt to fetch an opcode from '
                        f'offset 0x{offset:04X} of {name}')
        super().__init__(self.message)

class SetUseError(Disassem8Error):
    """
    Exception raised when attempting to change the use of a memory location.
    """
    def __init__(self, address: int, old_usage: str, new_usage: str):
        self.address = address
        self.old_usage = old_usage
        self.new_usage = new_usage
        self.message = (f'Attempt to set memory at 0x{address:04X} '
                        f'of type {old_usage} to type {new_usage}')
        super().__init__(self.message)

class UnknownUseError(Disassem8Error):
    """
    Exception raised when the use of a memory location is unknown.
    """
    def __init__(self, address: int, usage: str):
        self.address = address
        self.usage = usage
        self.message = f'The use {usage} of memory at 0x{address:04X} is unknown.'
        super().__init__(self.message)
class OpcodeInvalidError(Disassem8Error):
    """
    Exception raised when a fetched opcode is not recognized.
    """
    def __init__(self, address: int, opcode: int):
        self.address = address
        self.opcode = opcode
        self.message = (f'Invalid opcode 0x{opcode:02X} '
                        f'at address  0x{address:04X}')
        super().__init__(self.message)

class UnknownAddressingModeError(Disassem8Error):
    """
    Exception raised when the addressing mode is unexpected.
    """
    def __init__(self, address: int, addressing_mode: str):
        self.address = address
        self.addressing_mode = addressing_mode
        self.message = (f'Addressing mode {addressing_mode} at '
                        f'0x{address:04X} is unknown.')
        super().__init__(self.message)

class MemoryDevice():
    """Base class for devices that can be put in a memory map."""
    # pylint: disable=too-few-public-methods
    def __init__(self, name: str):
        self.name = name

    def __getitem__(self, offset: int) -> int:
        raise LocationAccessError(self.name, offset)

class ROM(MemoryDevice):
    """A trivial class to represent a programmed Read-Only Memory device."""
    # pylint: disable=too-few-public-methods
    def __init__(self, name: str, contents_filename: str):
        super().__init__(name)
        with open(contents_filename, 'rb') as rom_file:
            self.data = rom_file.read()

    def __len__(self) -> int:
        return len(self.data)

    def __getitem__(self, offset: int) -> int:
        return self.data[offset]

class MemoryMap():
    """
    Allows dereferencing the contents of various devices in a memory space.
    """
    # pylint: disable=too-few-public-methods
    def __init__(self,
                 device_list: Sequence[tuple[int, int, MemoryDevice]]):
        self.memory_map: dict[int, tuple[MemoryDevice, int]] = {}
        missing_device = MemoryDevice('nonexistant')
        for offset in range(0x10000):
            self.memory_map[offset] = (missing_device, offset)
        for base_address, length, device in reversed(device_list):
            for offset in range(length):
                self.memory_map[base_address + offset] = (device, offset)

    def __getitem__(self, address_in_memory_map: int) -> int:
        device, offset = self.memory_map[address_in_memory_map]
        return device[offset]

@dataclass
class Opcode():
    """Class to contain the data this code needs about an opcode."""
    mnemonic: str
    addressing_mode: str  # The following addressing modes are handled:
    #   'inherent':
    #      The operand(s) are inherent in the opcode.
    #   'immediate':
    #      The operand is the byte/word following the opcode.
    #   'direct':
    #      The operand is pointed to by the byte/word following the opcode.
    #   'relative':
    #      The operand is pointed to by adding the Program Counter to
    #      the byte/word following the opcode.
    #   'indexed':
    #      The operand is pointed to by adding the byte/word following
    #      the opcode to an inherently implied register.
    opcode_len: int = field(init=False)
    operand_len: int
    total_len: int = field(init=False)
    branches: bool = False  # Can this opcode cause a branch to the operand?
    continues: bool = True  # Does execution continue to the code that follows?

    def __str__(self) -> str:
        return f'{self.mnemonic} <{self.addressing_mode}>'

class CPU():
    """
    Base class for disassembling 8-bit von Neumann architecture CPU code.
    """
    opcodes = {
        b'\x01': Opcode('NOP', 'inherent', 0),
        b'\x06': Opcode('TAP', 'inherent', 0),
        b'\x07': Opcode('TPA', 'inherent', 0),
        b'\x08': Opcode('INX', 'inherent', 0),
        b'\x09': Opcode('DEX', 'inherent', 0),
        b'\x0A': Opcode('CLV', 'inherent', 0),
        b'\x0B': Opcode('SEV', 'inherent', 0),
        b'\x0C': Opcode('CLC', 'inherent', 0),
        b'\x0D': Opcode('SEC', 'inherent', 0),
        b'\x0E': Opcode('CLI', 'inherent', 0),
        b'\x0F': Opcode('SEI', 'inherent', 0),
        b'\x10': Opcode('SBA', 'inherent', 0),
        b'\x11': Opcode('CBA', 'inherent', 0),
        b'\x14': Opcode('NBA', 'inherent', 0),
        b'\x16': Opcode('TAB', 'inherent', 0),
        b'\x17': Opcode('TBA', 'inherent', 0),
        b'\x19': Opcode('DAA', 'inherent', 0),
        b'\x1B': Opcode('ABA', 'inherent', 0),
        b'\x20': Opcode('BRA', 'relative', 1, branches=True, continues=False),
        b'\x22': Opcode('BHI', 'relative', 1, branches=True),
        b'\x23': Opcode('BLS', 'relative', 1, branches=True),
        b'\x24': Opcode('BCC', 'relative', 1, branches=True),
        b'\x25': Opcode('BCS', 'relative', 1, branches=True),
        b'\x26': Opcode('BNE', 'relative', 1, branches=True),
        b'\x27': Opcode('BEQ', 'relative', 1, branches=True),
        b'\x28': Opcode('BVC', 'relative', 1, branches=True),
        b'\x29': Opcode('BVS', 'relative', 1, branches=True),
        b'\x2A': Opcode('BPL', 'relative', 1, branches=True),
        b'\x2B': Opcode('BMI', 'relative', 1, branches=True),
        b'\x2C': Opcode('BGE', 'relative', 1, branches=True),
        b'\x2D': Opcode('BLT', 'relative', 1, branches=True),
        b'\x2E': Opcode('BGT', 'relative', 1, branches=True),
        b'\x2F': Opcode('BLE', 'relative', 1, branches=True),
        b'\x30': Opcode('TSX', 'inherent', 0),
        b'\x31': Opcode('INS', 'inherent', 0),
        b'\x32': Opcode('PULA', 'inherent', 0),
        b'\x33': Opcode('PULB', 'inherent', 0),
        b'\x34': Opcode('DES', 'inherent', 0),
        b'\x35': Opcode('TXS', 'inherent', 0),
        b'\x36': Opcode('PSHA', 'inherent', 0),
        b'\x37': Opcode('PSHB', 'inherent', 0),
        b'\x39': Opcode('RTS', 'inherent', 0, continues=False),
        b'\x3B': Opcode('RTI', 'inherent', 0, continues=False),
        b'\x3E': Opcode('WAI', 'inherent', 0),
        b'\x3F': Opcode('SWI', 'inherent', 0),
        b'\x40': Opcode('NEGA', 'inherent', 0),
        b'\x43': Opcode('COMA', 'inherent', 0),
        b'\x44': Opcode('LSRA', 'inherent', 0),
        b'\x46': Opcode('RORA', 'inherent', 0),
        b'\x47': Opcode('ASRA', 'inherent', 0),
        b'\x48': Opcode('ASLA', 'inherent', 0),
        b'\x49': Opcode('ROLA', 'inherent', 0),
        b'\x4A': Opcode('DECA', 'inherent', 0),
        b'\x4C': Opcode('INCA', 'inherent', 0),
        b'\x4D': Opcode('TSTA', 'inherent', 0),
        b'\x4F': Opcode('CLRA', 'inherent', 0),
        b'\x50': Opcode('NEGB', 'inherent', 0),
        b'\x53': Opcode('COMB', 'inherent', 0),
        b'\x54': Opcode('LSRB', 'inherent', 0),
        b'\x56': Opcode('RORB', 'inherent', 0),
        b'\x57': Opcode('ASRB', 'inherent', 0),
        b'\x58': Opcode('ASLB', 'inherent', 0),
        b'\x59': Opcode('ROLB', 'inherent', 0),
        b'\x5A': Opcode('DECB', 'inherent', 0),
        b'\x5C': Opcode('INCB', 'inherent', 0),
        b'\x5D': Opcode('TSTB', 'inherent', 0),
        b'\x5F': Opcode('CLRB', 'inherent', 0),
        b'\x60': Opcode('NEG', 'indexed', 1),
        b'\x63': Opcode('COM', 'indexed', 1),
        b'\x64': Opcode('LSR', 'indexed', 1),
        b'\x66': Opcode('ROR', 'indexed', 1),
        b'\x67': Opcode('ASR', 'indexed', 1),
        b'\x68': Opcode('ASL', 'indexed', 1),
        b'\x69': Opcode('ROL', 'indexed', 1),
        b'\x6A': Opcode('DEC', 'indexed', 1),
        b'\x6C': Opcode('INC', 'indexed', 1),
        b'\x6D': Opcode('TST', 'indexed', 1),
        b'\x6E': Opcode('JMP', 'indexed', 1, branches=True, continues=False),
        b'\x6F': Opcode('CLR', 'indexed', 1),
        b'\x70': Opcode('NEG', 'direct', 2),
        b'\x73': Opcode('COM', 'direct', 2),
        b'\x74': Opcode('LSR', 'direct', 2),
        b'\x76': Opcode('ROR', 'direct', 2),
        b'\x77': Opcode('ASR', 'direct', 2),
        b'\x78': Opcode('ASL', 'direct', 2),
        b'\x79': Opcode('ROL', 'direct', 2),
        b'\x7A': Opcode('DEC', 'direct', 2),
        b'\x7C': Opcode('INC', 'direct', 2),
        b'\x7D': Opcode('TST', 'direct', 2),
        b'\x7E': Opcode('JMP', 'direct', 2, branches=True, continues=False),
        b'\x7F': Opcode('CLR', 'direct', 2),
        b'\x80': Opcode('SUBA', 'immediate', 1),
        b'\x81': Opcode('CMPA', 'immediate', 1),
        b'\x82': Opcode('SBCA', 'immediate', 1),
        b'\x84': Opcode('ANDA', 'immediate', 1),
        b'\x85': Opcode('BITA', 'immediate', 1),
        b'\x86': Opcode('LDAA', 'immediate', 1),
        b'\x87': Opcode('STAA', 'immediate', 1),
        b'\x88': Opcode('EORA', 'immediate', 1),
        b'\x89': Opcode('ADCA', 'immediate', 1),
        b'\x8A': Opcode('ORAA', 'immediate', 1),
        b'\x8B': Opcode('ADDA', 'immediate', 1),
        b'\x8C': Opcode('CPX', 'immediate', 2),
        b'\x8D': Opcode('BSR', 'relative', 1, branches=True),
        b'\x8E': Opcode('LDS', 'immediate', 2),
        b'\x8F': Opcode('STS', 'immediate', 1),
        b'\x90': Opcode('SUBA', 'direct', 1),
        b'\x91': Opcode('CMPA', 'direct', 1),
        b'\x92': Opcode('SBCA', 'direct', 1),
        b'\x94': Opcode('ANDA', 'direct', 1),
        b'\x95': Opcode('BITA', 'direct', 1),
        b'\x96': Opcode('LDAA', 'direct', 1),
        b'\x97': Opcode('STAA', 'direct', 1),
        b'\x98': Opcode('EORA', 'direct', 1),
        b'\x99': Opcode('ADCA', 'direct', 1),
        b'\x9A': Opcode('ORAA', 'direct', 1),
        b'\x9B': Opcode('ADDA', 'direct', 1),
        b'\x9C': Opcode('CPX', 'direct', 1),
        b'\x9D': Opcode('HCF', 'inherent', 0, continues=False),
        b'\x9E': Opcode('LDS', 'direct', 1),
        b'\x9F': Opcode('STS', 'direct', 1),
        b'\xA0': Opcode('SUBA', 'indexed', 1),
        b'\xA1': Opcode('CMPA', 'indexed', 1),
        b'\xA2': Opcode('SBCA', 'indexed', 1),
        b'\xA4': Opcode('ANDA', 'indexed', 1),
        b'\xA5': Opcode('BITA', 'indexed', 1),
        b'\xA6': Opcode('LDAA', 'indexed', 1),
        b'\xA7': Opcode('STAA', 'indexed', 1),
        b'\xA8': Opcode('EORA', 'indexed', 1),
        b'\xA9': Opcode('ADCA', 'indexed', 1),
        b'\xAA': Opcode('ORAA', 'indexed', 1),
        b'\xAB': Opcode('ADDA', 'indexed', 1),
        b'\xAC': Opcode('CPX', 'indexed', 1),
        b'\xAD': Opcode('JSR', 'indexed', 1, branches=True),
        b'\xAE': Opcode('LDS', 'indexed', 1),
        b'\xAF': Opcode('STS', 'indexed', 1),
        b'\xB0': Opcode('SUBA', 'direct', 2),
        b'\xB1': Opcode('CMPA', 'direct', 2),
        b'\xB2': Opcode('SBCA', 'direct', 2),
        b'\xB4': Opcode('ANDA', 'direct', 2),
        b'\xB5': Opcode('BITA', 'direct', 2),
        b'\xB6': Opcode('LDAA', 'direct', 2),
        b'\xB7': Opcode('STAA', 'direct', 2),
        b'\xB8': Opcode('EORA', 'direct', 2),
        b'\xB9': Opcode('ADCA', 'direct', 2),
        b'\xBA': Opcode('ORAA', 'direct', 2),
        b'\xBB': Opcode('ADDA', 'direct', 2),
        b'\xBC': Opcode('CPX', 'direct', 2),
        b'\xBD': Opcode('JSR', 'direct', 2, branches=True),
        b'\xBE': Opcode('LDS', 'direct', 2),
        b'\xBF': Opcode('STS', 'direct', 2),
        b'\xC0': Opcode('SUBB', 'immediate', 1),
        b'\xC1': Opcode('CMPB', 'immediate', 1),
        b'\xC2': Opcode('SBCB', 'immediate', 1),
        b'\xC4': Opcode('ANDB', 'immediate', 1),
        b'\xC5': Opcode('BITB', 'immediate', 1),
        b'\xC6': Opcode('LDAB', 'immediate', 1),
        b'\xC7': Opcode('STAB', 'immediate', 1),
        b'\xC8': Opcode('EORB', 'immediate', 1),
        b'\xC9': Opcode('ADCB', 'immediate', 1),
        b'\xCA': Opcode('ORAB', 'immediate', 1),
        b'\xCB': Opcode('ADDB', 'immediate', 1),
        b'\xCE': Opcode('LDX', 'immediate', 2),
        b'\xCF': Opcode('STX', 'immediate', 1),
        b'\xD0': Opcode('SUBB', 'direct', 1),
        b'\xD1': Opcode('CMPB', 'direct', 1),
        b'\xD2': Opcode('SBCB', 'direct', 1),
        b'\xD4': Opcode('ANDB', 'direct', 1),
        b'\xD5': Opcode('BITB', 'direct', 1),
        b'\xD6': Opcode('LDAB', 'direct', 1),
        b'\xD7': Opcode('STAB', 'direct', 1),
        b'\xD8': Opcode('EORB', 'direct', 1),
        b'\xD9': Opcode('ADCB', 'direct', 1),
        b'\xDA': Opcode('ORAB', 'direct', 1),
        b'\xDB': Opcode('ADDB', 'direct', 1),
        b'\xDD': Opcode('HCF', 'inherent', 0, continues=False),
        b'\xDE': Opcode('LDX', 'direct', 1),
        b'\xDF': Opcode('STX', 'direct', 1),
        b'\xE0': Opcode('SUBB', 'indexed', 1),
        b'\xE1': Opcode('CMPB', 'indexed', 1),
        b'\xE2': Opcode('SBCB', 'indexed', 1),
        b'\xE4': Opcode('ANDB', 'indexed', 1),
        b'\xE5': Opcode('BITB', 'indexed', 1),
        b'\xE6': Opcode('LDAB', 'indexed', 1),
        b'\xE7': Opcode('STAB', 'indexed', 1),
        b'\xE8': Opcode('EORB', 'indexed', 1),
        b'\xE9': Opcode('ADCB', 'indexed', 1),
        b'\xEA': Opcode('ORAB', 'indexed', 1),
        b'\xEB': Opcode('ADDB', 'indexed', 1),
        b'\xEE': Opcode('LDX', 'indexed', 1),
        b'\xEF': Opcode('STX', 'indexed', 1),
        b'\xF0': Opcode('SUBB', 'direct', 2),
        b'\xF1': Opcode('CMPB', 'direct', 2),
        b'\xF2': Opcode('SBCB', 'direct', 2),
        b'\xF4': Opcode('ANDB', 'direct', 2),
        b'\xF5': Opcode('BITB', 'direct', 2),
        b'\xF6': Opcode('LDAB', 'direct', 2),
        b'\xF7': Opcode('STAB', 'direct', 2),
        b'\xF8': Opcode('EORB', 'direct', 2),
        b'\xF9': Opcode('ADCB', 'direct', 2),
        b'\xFA': Opcode('ORAB', 'direct', 2),
        b'\xFB': Opcode('ADDB', 'direct', 2),
        b'\xFE': Opcode('LDX', 'direct', 2),
        b'\xFF': Opcode('STX', 'direct', 2)
    }

    big_endian = True
    vectors = [
        0xFFF8,  # IRQ Interrupt
        0xFFFA,  # SWI Software Interrupt
        0xFFFC,  # NMI Non-Maskable Interrupt
        0xFFFE   # RST Reset
    ]

    def __init__(self, memory: MemoryMap, args: argparse.Namespace):
        self.args = args
        self.max_opcode_len = 0
        for opcode_bytes, opcode in self.opcodes.items():
            opcode_len = len(opcode_bytes)
            opcode.opcode_len = opcode_len
            opcode.total_len = opcode_len + opcode.operand_len
            if opcode_len > self.max_opcode_len:
                self.max_opcode_len = opcode_len
        self.memory = memory
        self.memory_use: dict[int, str] = {}
        self.memory_referenced: set[int] = set()
        self.get_u16 = self.get_u16_be if self.big_endian else self.get_u16_le

    def __getitem__(self, address: int) -> int:
        return self.get_u8(address)

    def get_u8(self, address: int) -> int:
        """Fetch an unsigned 8-bit byte from the CPU's memory."""
        return self.memory[address]

    def get_u16_be(self, address: int) -> int:
        """Fetch a big-endian unsigned 16-bit word from the CPU's memory."""
        hi_byte = self.memory[address]
        lo_byte = self.memory[address + 1]
        return hi_byte << 8 | lo_byte

    def get_u16_le(self, address: int) -> int:
        """Fetch a little-endian unsigned 16-bit word from the CPU's memory."""
        hi_byte = self.memory[address + 1]
        lo_byte = self.memory[address]
        return hi_byte << 8 | lo_byte

    def process_vectors(self) -> None:
        """Process vectors to determine where code is present."""
        for addr in self.vectors:
            self.process_vector(addr)

    def set_memory_use(self,
                       use: str, address: int, num_bytes: int = 1) -> bool:
        """
        Set the usage of <num_bytes> of memory starting at <address> to <use>.

        If the usage of all the bytes starting <address> was already <use>,
        return True.  Raise SetUseError if the <use> of any of the bytes
        was already set to some other usage.  If the usage of any of the bytes
        hadn't been set before, return False.
        """
        all_set_correctly = True
        for use_address in range(address, address + num_bytes):
            if use_address in self.memory_use:
                if self.memory_use[use_address] == use:
                    continue
                raise SetUseError(use_address, self.memory_use[use_address], use)
            self.memory_use[use_address] = use
            all_set_correctly = False
        return all_set_correctly

    def find_opcode_bytes(self, address: int) -> bytes:
        """Find the opcode byte(s) in memory at <address>."""
        # Make a copy because MemoryMap is not slicable:
        memory_at_address = bytes(
            [self.memory[a]
             for a in range(address, address + self.max_opcode_len)])
        for opcode_bytes in self.opcodes:
            if opcode_bytes == memory_at_address[:len(opcode_bytes)]:
                return opcode_bytes
        raise OpcodeInvalidError(address, self.memory[address])

    def get_operand_and_len(self, address: int, opcode:Opcode) -> tuple[int, int]:
        """Return raw operand and its byte length for <opcode> at <address>."""
        if opcode.operand_len == 1:
            return (self.memory[address + opcode.opcode_len], 1)
        assert opcode.operand_len == 2
        return (self.get_u16(address + opcode.opcode_len), 2)
    # The operand_* methods are passed the address of the operand and the
    # bytes that make up the operand which can be used as a key into the
    # self.opcodes dict.  Each operand_* handles a different addressing mode.
    # They should call set_memory_use for any data that can be determined and
    # return a sequence of code addresses that should be traversed.
    def operand_inherent(self, address: int, opcode: Opcode) -> Sequence[int]:
        """
        Return tuple of following code addresses for inherent addressing mode.

        Branches are not possible, so either return a tuple with the following
        code address if execution continues, or an empty tuple if it doesn't
        (e.g. a return instruction).
        """
        assert not opcode.branches  # It's just not done...
        if opcode.continues:
            return (address + opcode.total_len, )
        return tuple()

    def operand_immediate(self, address: int, opcode: Opcode) -> Sequence[int]:
        """
        Return tuple of following code addresses for inherent addressing mode.

        Branches are not possible and execution always continues, so return a
        tuple with the following code address.
        """
        assert not opcode.branches and opcode.continues
        return (address + opcode.total_len, )

    def operand_direct(self, address: int, opcode: Opcode) -> Sequence[int]:
        """
        Return tuple of following code addresses for direct addressing mode.

        The returned tuple may contain 0, 1 or 2 addresses depending on
        whether the particular opcode continues execution after itself and
        whether the code can branch.
        """
        operand, _operand_len = self.get_operand_and_len(address, opcode)
        self.memory_referenced.add(operand)
        code_addresses = []
        if opcode.branches:
            code_addresses.append(operand)
        else:
            self.set_memory_use('data', operand, 1)
        if opcode.continues:
            code_addresses.append(address + opcode.total_len)
        return code_addresses

    def operand_relative(self, address: int, opcode: Opcode) -> Sequence[int]:
        """
        Return tuple of following code addresses for relative addressing mode.

        The returned tuple may contain 0, 1 or 2 addresses depending on
        whether the particular opcode continues execution after itself and
        whether the code can branch.
        """
        operand, operand_len = self.get_operand_and_len(address, opcode)
        if operand_len == 1:
            if operand > 0x7F:
                operand -= 0x100
        elif operand > 0x7FFF:
            # Does anything do 16-bit relative addressing?
            operand -= 0x10000
        operand = address + opcode.total_len + operand
        self.memory_referenced.add(operand)
        code_addresses = []
        if opcode.branches:
            code_addresses.append(operand)
        else:
            # Does anything do relative addressing for code?
            self.set_memory_use('data', operand, 1)
        if opcode.continues:
            code_addresses.append(address + opcode.total_len)
        return code_addresses

    def operand_indexed(self, address: int, opcode: Opcode) -> Sequence[int]:
        """
        Return tuple of following code addresses for indexed addressing mode.

        Determining the addresses targeted by indexed addressing would require
        emulating the CPU to know what is in the index register.  This program
        does not do that so they will need to be manually followed.

        The returned tuple may contain 0 or 1 addresses depending on whether
        the particular opcode continues execution after itself.
        """
        operand, operand_len = self.get_operand_and_len(address, opcode)
        if self.args.notify_unfollowed:
            print(f'Not following indexed '
                  f'{"code" if opcode.branches else "data"} '
                  f'0x{operand:0{operand_len*2}X} '
                  f'from address 0x{address:04X}', file=sys.stderr)
        if opcode.continues:
            return (address + opcode.total_len, )
        return tuple()

    def process_opcode(self, address: int) -> int:
        """
        Start processing opcodes at <address>.

        The number of opcodes discovered is returned.
        """
        opcode_bytes = self.find_opcode_bytes(address)
        opcode = self.opcodes[opcode_bytes]

        opcode_covered = self.set_memory_use('opcode',
                                             address, opcode.opcode_len)
        operand_covered = self.set_memory_use(opcode.addressing_mode,
                                              address + opcode.opcode_len,
                                              opcode.operand_len)
        if opcode_covered and operand_covered:
            return 0  # No need for further processing

        hexdump = f'0x{address:04X}: '
        for byte in [self.memory[address + o] for o in range(opcode.total_len)]:
            hexdump = f'{hexdump} 0x{byte:02X}'
        print(f'{hexdump:24} {opcode}')

        operand_method = getattr(self, f'operand_{opcode.addressing_mode}')
        opcodes_processed = 1
        for to_process in operand_method(address, opcode):
            opcodes_processed += self.process_opcode(to_process)
        return opcodes_processed

    def process_vector(self, address: int) -> None:
        """Fetch an address of code from <address> and process it."""
        if self.set_memory_use('vector', address, 2):
            return
        code_address = self.get_u16(address)
        if self.args.notify_vectors:
            print(f'Vector at 0x{address:04X} points to code at '
                  f'0x{code_address:04X}', file=sys.stderr)
        self.memory_referenced.add(code_address)
        self.process_opcode(code_address)

    def process_potential_code(self, address: int) -> int:
        """
        Try to process opcodes at <address>.

        Save self.memory_use before trying and if any of our exceptions occur,
        restore self.memory_use to abandon any progress.

        Return the number of opcodes discovered.
        """
        saved_memory_use = self.memory_use.copy()
        saved_memory_referenced = self.memory_referenced.copy()
        try:
            return self.process_opcode(address)
        except Disassem8Error:
            self.memory_use = saved_memory_use
            self.memory_referenced = saved_memory_referenced
            return 0

    def process_code_gaps(self) -> None:
        """
        Try to find code in unknown memory immediately after discovered code.

        If an exception occurs, abandon that area as still unknown.
        """
        last_address = -2
        last_mem_type = 'data'
        while True:
            found = 0
            for address in sorted(self.memory_use):
                mem_type = self.memory_use[address]
                if (address != last_address + 1
                    and last_mem_type not in {'data', 'vector'}):
                    found += self.process_potential_code(last_address + 1)
                last_address = address
                last_mem_type = mem_type
            # Check if there is a gap after code at the end of memory
            if (last_mem_type not in {'data', 'vector'}
                and last_address < 0xFFFF):
                found += self.process_potential_code(last_address + 1)
            if not found:
                break

def main() -> int:
    """The main event."""
    args = parse_args()
    rom_5c = ROM('ROM_5C', args.rom_file)
    # The first quarter (16KB) of the EPROM is not addressable:
    rom_5c.data = rom_5c.data[0x4000:]
    assert len(rom_5c) == 0xC000

    memory_map = MemoryMap(((0x0000, 0x2000, MemoryDevice('RAM')),

                            # 6821 5F is at 3E on page 3 of the CPU schematics.
                            # It is used for solenoid drivers 9 through 16.
                            (0x2100, 0x0100, MemoryDevice('6821 5F')),

                            # 74LS273 5H is at 4D on page 3 of the CPU schem.
                            # It is used for solenoid drivers 1 through 8.
                            (0x2200, 0x0100, MemoryDevice('74LS273 5H')),

                            # 6821 11D is at 3B on page 3 of the CPU schematics.
                            # It is used for the lamp matrix.
                            (0x2400, 0x0400, MemoryDevice('6821 11D')),

                            # 6821 11B is at 4C on page 2 of the CPU
                            # schematics.  It is used for the DMD, printer,
                            # diagnostic switches, #BLANKING and PIA LED on CPU
                            # board.
                            (0x2800, 0x0400, MemoryDevice('6821 11B')),

                            # 6821 9B is at 10B on page 2 of the CPU schematics.
                            # It is used for the alphanumeric segment drivers
                            # and sound drivers.
                            (0x2C00, 0x0400, MemoryDevice('6821 9B')),

                            # 6821 8H is at 4E on page 2 of the CPU schematics.
                            # It is used for the switch matrix.
                            (0x3000, 0x0400, MemoryDevice('6821 8H')),

                            # 6821 7B is at 10E on page 2 of the CPU schematics.
                            # It is used for the alphanumeric segment drivers
                            # and sound drivers.
                            (0x3400, 0x0400, MemoryDevice('6821 7B')),

                            (0x4000, len(rom_5c), rom_5c)))

    cpu = CPU(memory_map, args)
    cpu.process_vectors()
    cpu.process_code_gaps()

    begin_address = 0
    last_address = 0
    current_type = None
    for used_address in sorted(cpu.memory_use):
        mem_type = ('data'
                    if cpu.memory_use[used_address] in {'data', 'vector'} else
                    'code')
        if mem_type != current_type or used_address != last_address + 1:
            if current_type:
                print(f'0x{begin_address:04X}-0x{last_address:04X}: {mem_type}')
            current_type = mem_type
            begin_address = last_address = used_address
        else:
            last_address = used_address
        # SAATODO: dump the last chunk

    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('Keyboard interrupt', file=sys.stderr)
    except BrokenPipeError:
        print('Broken pipe', file=sys.stderr)
    sys.exit(255)
