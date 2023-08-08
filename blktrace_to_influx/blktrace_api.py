from enum import Enum, Flag, auto
from io import IOBase
import struct
from dataclasses import dataclass
from typing import Any, Tuple, Optional


class TraceCategory(Flag):
    READ = 1 << 16
    WRITE = 1 << 17
    FLUSH = 1 << 18
    SYNC = 1 << 19
    QUEUE = 1 << 20  # queueing/merging
    REQUEUE = 1 << 21
    ISSUE = 1 << 22
    COMPLETE = 1 << 23
    FS = 1 << 24
    PC = 1 << 25
    NOTIFY = 1 << 26  # special message
    AHEAD = 1 << 27
    META = 1 << 28
    DISCARD = 1 << 29
    DRV_DATA = 1 << 30  # binary driver data
    FUA = 1 << 31
    END = FUA

    @classmethod
    def to_value(cls, category, action=None) -> int:
        v = category.value
        if action is not None:
            v = v + action.value

        return v

    @classmethod
    def from_value(cls, value: int):
        v = (value & 0xffff0000)
        category = cls(v)
        return category


class _TraceAction(Enum):
    NONE = 0
    QUEUE = 1  # queued
    BACKMERGE = auto()  # back merged to existing rq
    FRONTMERGE = auto()  # front merge to existing rq
    GETRQ = auto()  # allocated new request
    SLEEPRQ = auto()  # sleeping on rq allocation
    REQUEUE = auto()  # request requeued
    ISSUE = auto()  # sent to driver
    COMPLETE = auto()  # completed by driver
    PLUG = auto()  # queue was plugged
    UNPLUG_IO = auto()  # queue was unplugged by io
    UNPLUG_TIMER = auto()  # queue was unplugged by timer
    INSERT = auto()  # insert request
    SPLIT = auto()  # bio was split
    BOUNCE = auto()  # bio was bounced
    REMAP = auto()  # bio was remapped
    ABORT = auto()  # reauest aborted
    DRV_DATA = auto()  # binary driver data
    CGROUP = 1 << 8


class TraceAction(Enum):
    QUEUE = TraceCategory.to_value(TraceCategory.QUEUE, _TraceAction.QUEUE)
    BACKMERGE = TraceCategory.to_value(TraceCategory.QUEUE, _TraceAction.BACKMERGE)
    FRONTMERGE = TraceCategory.to_value(TraceCategory.QUEUE, _TraceAction.FRONTMERGE)
    GETRQ = TraceCategory.to_value(TraceCategory.QUEUE, _TraceAction.GETRQ)
    SLEEPR = TraceCategory.to_value(TraceCategory.QUEUE, _TraceAction.SLEEPRQ)

    REQUEUE = TraceCategory.to_value(TraceCategory.REQUEUE, _TraceAction.REQUEUE)

    ISSUE = TraceCategory.to_value(TraceCategory.ISSUE, _TraceAction.ISSUE)

    COMPLETE = TraceCategory.to_value(TraceCategory.COMPLETE, _TraceAction.COMPLETE)

    PLUG = TraceCategory.to_value(TraceCategory.QUEUE, _TraceAction.PLUG)
    UNPLUG_IO = TraceCategory.to_value(TraceCategory.QUEUE, _TraceAction.UNPLUG_IO)
    UNPLUG_TIMER = TraceCategory.to_value(TraceCategory.QUEUE, _TraceAction.UNPLUG_TIMER)

    INSERT = TraceCategory.to_value(TraceCategory.QUEUE, _TraceAction.INSERT)
    SPLIT = _TraceAction.SPLIT.value
    BOUNCE = _TraceAction.BOUNCE.value

    REMAP = TraceCategory.to_value(TraceCategory.QUEUE, _TraceAction.REMAP)
    ABORT = TraceCategory.to_value(TraceCategory.QUEUE, _TraceAction.ABORT)
    DRV_DAT = TraceCategory.to_value(TraceCategory.DRV_DATA, _TraceAction.DRV_DATA)

    CGROUP = _TraceAction.CGROUP.value


class TraceNotify(Enum):
    PROCESS = 0  # establish pid/name mapping
    TIMESTAMP = auto()  # include system clock
    MESSAGE = auto()  # character string message


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
        """ Force validation of the magic bytes andthe serial number. """
        self.verify_trace()

    def as_timepair(self) -> (int, int):
        """ Return the time as a pair (seconds, nanoseconds) """
        return divmod(self.time, 1000000000)

    def as_maj_min(self) -> (int, int):
        """ Return the device number as a pair of major and minor device number.

        There are 20 bits in a minor device number, so the minor mask is 0xffffff (5 f).
        The upper part of the int32 is used for major (at most 4096 major device numbers).
        """
        major = (self.device & 0xfff00000) >> 20
        minor = self.device & 0x000fffff
        return major, minor


def classify(value: int) -> Tuple[TraceCategory, TraceNotify | _TraceAction, int]:
    tc = None
    tn = None
    ta = None
    cg = 0

    hi = (value & 0xffff0000) >> 16
    lo = value & 0x0000ffff
    print(f"DEBUG: {hi:b} {lo:b}")

    tc = TraceCategory(value & 0xffff0000)
    if tc == TraceCategory.NOTIFY:
        tr = TraceNotify(value & 0x0000ff7f)
    else:
        tr = _TraceAction(value & 0x0000ff7f)

    cg = value & 0x00000080

    return tc, tr, cg


def fetch_blkparse_record(f: IOBase) -> Optional[BlkparseRecord]:
    the_record = struct.Struct("iilliiiiihh")

    # read the record and tentatively unpack it
    try:
        buf = f.read(the_record.size)
        unpacked = the_record.unpack(buf)
    except IOError:
        return None
    except struct.error:
        return None

    # Read optional record extension (extension length is the last field)
    pdu_data = None
    if unpacked[-1] > 0:
        pdu_data = f.read(unpacked[-1])

    return BlkparseRecord(*unpacked, pdu_data=pdu_data)
