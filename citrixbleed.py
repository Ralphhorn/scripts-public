#!/Users/ralphhorn/.pyenv/versions/dissect-venv/bin/python
from typing import Iterator, Optional
from pathlib import Path
from datetime import datetime
import textwrap
import statistics
import argparse
import logging
import structlog
from dissect.target import Target,filesystem
import os
import re
import sys
import pandas as pd
import gzip
print('success')

try:
    import structlog
    from dissect.target import Target
    from dissect.target.exceptions import UnsupportedPluginError
    from dissect.target.tools.info import print_target_info
    from flow.record import RecordDescriptor,RecordWriter
    from tabulate import tabulate

except ImportError:
    print("Please install dependencies using `pip install -r requirements.txt`")
    exit()

logging.getLogger("dissect.target.target").setLevel(logging.ERROR)

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.dev.ConsoleRenderer(),
    ]
)
log = structlog.get_logger()

Possible_citrixbleed_session = RecordDescriptor(
    "citrix/session_mismatch",
    [
        ("string", "type"),
        ("datetime", "logtime"),
        ("string", "user"),
        ("string", "session_id"),
        ("net.ipaddress", "source_ip"),
        ("net.ipaddress", "client_ip"),
        ("net.ipaddress", "nat_ip"),
        ("net.ipaddress", "destination_ip"),
        ("net.ipaddress", "vserver_ip"),
        ("string","duration")
    ],
)

def check_ns_log_line(log_line:bytes):
    # Define a pattern to extract details from TCPCONNSTAT events
    pattern = re.compile(r"""
        (\w+\s+\d+\s+\d+:\d+:\d+)                  # Date and time
        \s+<([^>]+)>\s+(\d+\.\d+\.\d+\.\d+)        # Log level and IP address
        \s+(\d+/\d+/\d+:\d+:\d+:\d+\sGMT)          # Timestamp
        \s+(CTX-ADC\s+\d+-PPE-\d+)\s+:\s+default   # Device and process
        \s+SSLVPN\s+TCPCONNSTAT\s+\d+\s+\d+\s+:    # Message type
        .+?SessionId:\s+(\d+)                      # Session ID
        .+?User\s+(\w+)                            # User
        .+?Client_ip\s+(\d+\.\d+\.\d+\.\d+)        # Client IP
        .+?Nat_ip\s+(\d+\.\d+\.\d+\.\d+)           # NAT IP
        .+?Vserver\s+(\d+\.\d+\.\d+\.\d+)          # Vserver IP
        :(\d+)                                     # Vserver port
        .+?Source\s+(\d+\.\d+\.\d+\.\d+)           # Source IP
        :(\d+)                                     # Source port
        .+?Destination\s+(\d+\.\d+\.\d+\.\d+)      # Destination IP
        :(\d+)                                     # Destination port
        .+?Duration\s+(\d+:\d+:\d+)\s              # duration
        .+?Total_bytes_send\s+(\d+)                # Bytes sent
        .+?Total_bytes_recv\s+(\d+)                # Bytes received
        """, re.VERBOSE)
    decoded_log_line = log_line.decode('utf-8')
    match = pattern.search(decoded_log_line)
    if match:
        date_time_raw, log_level, netscaler_ip, timestamp_raw, LogSource, extracted_session_id, extracted_user, extracted_client_ip, extracted_nat_ip, extracted_vserver_ip, vserver_port, extracted_source_ip, source_port, extracted_destination_ip,destination_port, extracted_duration, bytes_sent, bytes_recv = match.groups()
        timestamp= datetime.strptime(timestamp_raw, '%m/%d/%Y:%H:%M:%S %Z') 
        if extracted_source_ip != extracted_client_ip:
            processed_log= Possible_citrixbleed_session(
                type = "session/citrixbleed",
                logtime = timestamp,
                user = extracted_user,
                session_id = extracted_session_id,
                source_ip = extracted_source_ip,
                client_ip = extracted_client_ip,
                nat_ip = extracted_nat_ip,
                vserver_ip = extracted_vserver_ip,
                destination_ip = extracted_destination_ip,
                duration = extracted_duration,
                )
            return processed_log
        
def process_ns_log_file(file_entry: filesystem.RootFilesystemEntry):
    #log.error("check if gzip or uncompressed")
    print("processing log file")
    if file_entry.path.endswith(".gz"):
        #log.error("process gzip file")
        with gzip.open(file_entry.open(),mode='rb') as file:
            for line in file.readlines():
                check_ns_log_line(line)
    else:
        check_ns_log_line(file_entry.open())
                

def check_target(target: Target) -> Optional[Iterator[Possible_citrixbleed_session]]:
    # I. Check for CitrixBleed hijacked sessions
    #log.info("Getting all ns.log items")
    #ns_logs=[nslog for nslog in target.fs.listdir("/var/log") if nslog.startswith("ns.log")]
    ns_logs = target.fs.glob_ext("/var/log/ns.log*")
   
   
    for ns_log in ns_logs:
        #log.error("check if gzip file")
        if ns_log.path.endswith(".gz"):
            with gzip.open(ns_log.open(),mode="rb") as file:
                lines = file.readlines()
        else: 
            lines = ns_log.open().readlines()
        
        for line in lines:
            yield check_ns_log_line(line)
    



def main(target_paths: list, show_info: bool) -> None:
    for target_path in target_paths:
        if not Path(target_path).exists():
            log.warning(f"File {target_path} does not exist!")
            continue

        log.info(f"Scanning target {target_path}")
        target = Target.open(target_path)

        if target.os != "citrix-netscaler":
            log.warning(
                f"Target {target_path} not recognised as a Citrix Netscaler system ({target.os}).")
            continue

        if show_info:
            print("")
            print_target_info(target)
            print("")

        hits = list(filter(lambda hit: hit is not None,list(check_target(target))))
        with RecordWriter("citrixbleed.records.gz") as writer:
            for hit in hits:
                writer.write(hit)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyse forensic images of Citrix Netscaler systems", formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=textwrap.dedent('''\
    Investigate a Citrix Netscaler ADC system using the methodology described by mandiant in https://cloud.google.com/blog/topics/threat-intelligence/session-hijacking-citrix-cve-2023-4966.
    This script will check if there is a mismatch between the Client_ip and Source fields in the TCPCONNSTAT events logged in ns.log. 
    Mismatches can be benign and will require further manual analysis.
    This script will provide you with all mismatched sessions (and session information) number of accounts logged in from a given system.
    
    Script structure based on the JSCU-NL coathanger check (https://github.com/JSCU-NL/COATHANGER)
    '''))
    parser.add_argument("targets", nargs="+",
                        help="path(s) of target(s) to check")
    parser.add_argument("--info", action="store_true",
                        help="print basic Citrix Netscaler system information")
    parser.add_argument("--citrixbleed", action="store_true",
                        help="Check for Citrixbleed hijacked sessions")

    args = parser.parse_args()

    try:
        main(args.targets, args.info)
    except Exception as e:
        log.error("The script has crashed!", exc_info=e)
