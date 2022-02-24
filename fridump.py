#!/usr/bin/env python3

import asyncio
import argparse
import logging
import os
import sys

import frida
import frida.core


logo = """
______    _     _
|  ___|  (_)   | |
| |_ _ __ _  __| |_   _ _ __ ___  _ __
|  _| '__| |/ _` | | | | '_ ` _ \| '_ \\
| | | |  | | (_| | |_| | | | | | | |_) |
\_| |_|  |_|\__,_|\__,_|_| |_| |_| .__/
                                 | |
                                 |_|

Modified version of Fridump (https://github.com/Nightbringer21/fridump)
"""


# Modify to adjust focus level
LOGGING_LEVEL = logging.INFO
logging.basicConfig(format="[%(asctime)s][%(levelname)s] %(message)s")
logger = logging.getLogger("fridump")
logger.setLevel(LOGGING_LEVEL)

FRIDA_SCRIPT = """
'use strict';

rpc.exports = {
  enumerateRanges: function (prot) {
    return Process.enumerateRangesSync(prot);
  },
  readMemory: function (address, size) {
    return Memory.readByteArray(ptr(address), size);
  }
};
"""
# Maximum size of each dump file in bytes, 20MB by default.
# MAX_SIZE = 20971520
MAX_SIZE = 100000000


async def dump_to_file(agent, base: int, size: int, outpath: str) -> None:
    """
    A helper to read a block of memory and write it to disk. We require
    this abstraction to have a single point of Exception handling for things
    like access violations.

    Args:
        agent: : the session used to communicate with Frida
        base: int: the base address to start reading memory
        size: int: how much memory to read
        outpath: str: where to write the memory to disk

    Returns
        None
    """
    mem = None
    try:
        mem = agent.read_memory(base, size)
    except Exception as e:
        # If read fails, it's likely due to an access violation
        logging.debug(f"[!] {e}")
        return

    # Write the dumped page to disk
    with open(outpath, "wb") as fout:
        fout.write(mem)


async def main(process: str, outpath: str = "dump"):
    """
    Main entry point for dumping the volatile memory of a running app.

    Args:
        process: str: The name of the process to dump
        outpath: str: An optional path to where the artifacts should be dumped

    Returns:
        None
    """

    if not os.path.exists(outpath):
        os.path.makedirs(outpath)

    # Connect to session with frida
    session = None
    try:
        session = frida.get_usb_device().attach(process)
    except Exception as e:
        logger.error(f"Failed to start Frida session with {e}")
        # Let's add logic here that will try to start Frida server
        # if it's not already running. I'm going to setup EoS to
        # provision the binary to /data/local/eos/frida-server
        # start_frida_server()
        return

    script = session.create_script(FRIDA_SCRIPT)
    script.load()
    agent = script.exports

    # What memory pages to scan, for a "wider" scan of memory set
    # this to be 'r--' for any "readable" memory page
    regions = agent.enumerate_ranges("rw-")

    logger.info(f"Starting dump of {process}")

    # Performing the memory dump, consider bringing in tqdm for progress bar.
    for region in regions:
        # Note: we might be able to do some filtering here based off of the
        # `file` value of the region, as it's included sometimes:
        # {'base': '0xec521000', 'size': 4096, 'protection': 'rw-', 'file': {'path': '/system/lib/liblz4.so', 'offset': 57344, 'size': 0}}
        # Perhaps this could facilitate some filtering.

        base = int(region["base"], 16)
        size = int(region["size"])

        if size > MAX_SIZE:
            logging.info("Too big, splitting the dump into chunks")

            num_chunks = int(size / MAX_SIZE)
            for i in range(num_chunks):
                cur_base = base + (i * MAX_SIZE)
                await dump_to_file(
                    agent,
                    cur_base,
                    MAX_SIZE,
                    os.path.join(outpath, f"{cur_base}_dumped.data"),
                )

            # If needed, read the final chunk if the region isn't
            # perfectly divisible by our `max_size` value
            if (diff := size % MAX_SIZE) != 0:
                tmp_base = base + (int(size / MAX_SIZE) * MAX_SIZE)
                await dump_to_file(
                    agent,
                    tmp_base,
                    diff,
                    os.path.join(outpath, f"{tmp_base}_dumped.data"),
                )

        else:
            await dump_to_file(
                agent, base, size, os.path.join(outpath, f"{base}_dumped.data")
            )

    logger.info(f"Done. Wrote {len(regions)} artifacts to {outpath}")


if __name__ == "__main__":

    print(logo)

    ap = argparse.ArgumentParser()

    ap.add_argument("process", help="The target process to dump volatile memory for")
    ap.add_argument(
        "-o",
        "--output",
        default="./dump",
        help="The output directory. Defaults to './dump'",
    )

    args = ap.parse_args()
    asyncio.run(main(args.process, args.output))
