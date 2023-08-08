from typing import Optional

from blktrace_to_influx.blktrace_api import BlkparseRecord

class GlobalState:

    def __init__(self):
        self.ppm = dict()
        self.debug = False
        self.start_timestamp = (0,0)
        self.abs_timestamp = (0,0)

    def __repr__(self):
        return f"GlobalState(debug={self.debug}, start_timestamp={self.start_timestamp}, abs_timestamp={self.abs_timestamp}, ppm={self.ppm})"

    def add_program(self, r: BlkparseRecord):
        pid = r.pid
        offset = r.pdu_data.find(b'\0')
        if offset:
            program = r.pdu_data[0:offset].decode('utf_8')
        else:
            program = r.pdu_data.decode('utf_8')

        self.ppm[pid] = program
        print(f"add_program({pid=}, {program=})")

    def ppm_by_pid(self, pid: int) -> Optional[str]:
        return self.ppm.get(pid, None)
