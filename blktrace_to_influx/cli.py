import struct
import sys
from pathlib import Path

import click

from blktrace_to_influx.global_state import GlobalState
from blktrace_to_influx.blktrace_api import *


@click.group(help="Import blktrace files into Influx")
@click.option("--debug/--no-debug", default=False, envvar="BLKFLUX_DEBUG")
@click.pass_context
def cli(ctx, debug):
    ctx.obj = GlobalState()
    ctx.obj.debug = debug


@cli.command()
@click.option('-D', '--directory', default=".")
@click.argument('filename')
@click.pass_obj
def dumpfile(g: GlobalState, filename: str, directory: str):
    full_filename = Path(directory) / filename
    try:
        with open(full_filename, "rb") as f:
            while r := fetch_blkparse_record(f):
                print(r)
                print(classify(r.action))
                print()

                tc, tn, cg = classify(r.action)
                if TraceCategory.NOTIFY in tc:
                    if tn == TraceNotify.PROCESS:
                        g.add_program(r)
                        continue

                    if tn == TraceNotify.TIMESTAMP:
                        if r.pdu_len != 8:
                            raise (ValueError(f'TraceNotify.TIMESTAMP has payload len != 8, {r}'))

                        g.start_timestamp = r.as_timepair()
                        sec, nanosec = struct.Struct('ii').unpack(r.pdu_data)
                        if nanosec < 0:
                            sec -= 1
                            nanosec += 1000000000
                        g.abs_timestamp = sec, nanosec
                        continue

                    if tn == TraceNotify.MESSAGE:
                        raise (ValueError('tn.MESSAGE'))

    except IOError as e:
        print(f"Error reading file {full_filename}: {e}")
        sys.exit(1)


@cli.command()
@click.pass_context
def test(ctx):
    print(f"{ctx.obj.debug=}")
    print(TraceCategory.NOTIFY)
    print(TraceCategory.to_value(TraceCategory.NOTIFY))
