#!/usr/bin/env python3

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


async def dump_to_file(mem: bytes, outpath: str) -> None:
    # Write the dumped page to disk
    try:
        # with open(os.path.join(directory, f"{base}_dump.data"), "wb") as fout:
        with open(outpath, "wb") as fout:
            fout.write()
    except Exception as e:
        # Likely hit a memory access violation, consider supressing this.
        logging.warning("[!]" + str(e))


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
        if USB:
            session = frida.get_usb_device().attach(process)
        else:
            session = frida.attach(process)
    except Exception as e:
        logger.error("Failed to attach to process, is frida-server running on device?")
        logger.error(e)
        sys.exit(1)

    script = session.create_script(FRIDA_SCRIPT)
    script.on("message", utils.on_message)
    script.load()
    agent = script.exports

    # What memory pages to scan, for a "wider" scan of memory set
    # this to be 'r--' for any "readable" memory page
    ranges = agent.enumerate_ranges("rw-")

    # Performing the memory dump, consider bringing in tqdm for progress bar.
    for range in ranges:
        base = range["base"]
        size = range["size"]

        if size > MAX_SIZE:
            logging.info("Too big, splitting the dump into chunks")

            num_chunks = int(size / max_size)
            for i in range(num_chunks):
                cur_base = base + (i * max_size)
                mem = agent.read_memory(cur_base, max_size)
                await dump_to_file(
                    mem, os.path.join(outpath, f"{cur_base}_dumped.data")
                )

            # If needed, read the final chunk if the page isn't perfectly
            # divisible by our `max_size` value
            if (diff := size % max_size) != 0:
                tmp_base = base + (int(size / max_size) * max_size)
                mem = agent.read_memory(tmp_base, diff)
                await dump_to_file(
                    mem, os.path.join(outpath, f"{tmp_base}_dumped.data")
                )

        else:
            mem = agent.read_memory(base, size)
            await dump_to_file(mem, os.path.join(outpath, f"{base}_dumped.data"))


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
