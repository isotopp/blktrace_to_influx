import sys
from pathlib import Path
from io import IOBase
from struct import Struct
from dataclasses import dataclass
from typing import Any

import click



@dataclass(frozen=True, slots=True)
class BlkparseRecord:
    magic: int  # 0x65617400 || version (currently: 7)
    sequence: int  # event number
    time: int  # in nanoseconds
    sector: int  # disk offset
    bytes: int  # transfer length
    action: int  # what happened
    pid: int  # who did it
    device: int  # device number
    cpu: int  # on what cpu did it happen
    error: int  # completion error
    pdu_len: int  # length of data after this trace
    pdu_data: Any  # The PDU content

    def verify_trace(self) -> bool:
        magic_mask = 0xffffff00
        magic_expected = 0x65617400
        version_mask = 0x000000ff
        version_expected = 7

        m = self.magic & magic_mask
        if m != magic_expected:
            raise ValueError(f'Magic Byte found {m:x}, expected {magic_expected:x}')

        version = self.magic & version_mask
        if version != version_expected:
            raise ValueError(f'Version found {version}, expected {version_expected}')

        return True

    def __post_init__(self):
        self.verify_trace()

    def as_datetime(self) -> (int, int):
        return divmod(self.time, 1000000000)

    def as_maj_min(self) -> (int, int):
        """ Convert a device number to a pair of major and minor device numbers.

        There are 20 bits in a minor device number, so the minor mask is 0xffffff (5 f).
        The upper part of the int32 is used for major (at most 4096 major device numbers).
        """
        major = (self.device & 0xfff00000) >> 20
        minor = self.device & 0x000fffff
        return major, minor


def fetch_blkparse_record(f: IOBase) -> BlkparseRecord:
    the_record = Struct("iilliiiiihh")

    # read the record and tentatively unpack it
    buf = f.read(the_record.size)
    unpacked = the_record.unpack(buf)

    # Read optional record extension (extension length is the last field)
    pdu_data = None
    if unpacked[-1] > 0:
        pdu_data = f.read(unpacked[-1])

    return BlkparseRecord(*unpacked, pdu_data=pdu_data)


@click.group(help="Import blktrace files into Influx")
def main():
    pass


@main.command()
@click.option('-D', '--directory', default=".")
@click.argument('filename')
def dumpfile(filename: str, directory: str):
    full_filename = Path(directory) / filename
    try:
        with open(full_filename, "rb") as f:
            r = fetch_blkparse_record(f)
            print(r)
    except IOError as e:
        print(f"Error reading file {full_filename}: {e}")
        sys.exit(1)
