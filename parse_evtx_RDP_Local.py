#! /usr/bin/env python3
# Find specific Events associated with RDP connections
# by parsing the following Windows event logs:
# This script parses:
# Microsoft-Windows-TerminalServices-LocalSessionManager/Operational.evtx
#
# Other Windows Event Logs with RDP Information:
# Microsoft-Windows-TerminalServices-RemoteConnectionManager.evtx
# Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational.evtx      
# Security.evtx
# System.evtx
#
#
# https://www.13cubed.com/downloads/rdp_flowchart.pdf
# https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/
# Requires Python-evtx https://github.com/williballenthin/python-evtx
# and BeautifulSoup
# Event IDs can be added or removed by editing the "evtxs" variable

import sys
import re
import mmap
import contextlib

import argparse
from bs4 import BeautifulSoup, element

from Evtx.Evtx import FileHeader
from Evtx.Views import evtx_file_xml_view

RDP_local_IDs = {21: 'RDP Session logon success',
 22: 'RDP Shell start notification received',
 23: 'RDP Session logoff',
 24: 'RDP Session has been disconnected',
 25: 'RDP Session reconnection success',
 39: 'RDP Session <X> disconnected by session <Y>',
 40: 'RDP Session <X> disconnected, reason code <Z>',
}

RDP_remote_IDs = {
261: 'RDP-TCP received a connection', 
1149: 'RDP Login screen accessed',
1006: 'Large Number of Connection Attempts' 
}

RDP_info = ('user',
'address',
'session',
'sessionid',
'source',
'targetsession',
'reason'
)

RDP_core_IDs = {98: 'RDP Successful Connection',
131: 'RDP accepted a new TCP connection from IP x.x.x.x',
140: 'RDP connection Failed IP x.x.x.x incorect password'
}

Security_evtxs = {1102: 'Log Cleared',
4624: 'User logon',
4625: 'Login Failed',
4634: 'Logoff',
4647: 'User Initiated logoff',
4648: 'Attempted Login by a process',
4672: 'Administrator Logon',
4740: 'Account Locked out',
4776: 'NTLM Credential Auth',
4778: 'Reconnect(RDP or FastUser Switch)',
4779: 'Disconnect(RDP or FastUser Switch)'
}

System_evtxs = {
56: 'RDP TS Error client disconnect',
9009: 'Desktop Window Manager exited'
}

event_info_names = ('Date',
'EventID',
'Description',
'Computer'
)

event_data_names = ('LogonType',
'AuthenticationPackageName',
'LmPackageName',
'LogonProcessName',
'SubjectUserSID',
'IpAddress',
'IpPort',
'WorkstationName',
'SubjectUserSid',
'SubjectUserName',
'SubjectDomainName',
'SubjectLogonId',
'TargetUserSid',
'TargetUserName',
'TargetDomainName',
'TargetLogonId',
'LogonGuid',
'TransmittedServices',
'KeyLength',
'ProcessName',
'ProcessId'
)

# Event header contains values for other EVTX files for concatenation
RDP_Header = 'Date,EventID,Description,Computer,User,IP Address,'\
'Session,Sessionid,Source,TargetSession,Reason,ListenerName,Domain'

def main():
    parser = argparse.ArgumentParser(description=
        "Find RDP Logon Events in Windows evtx files and output CSV",
        usage='parse_evtx_RDP.py evtx-file -n -i -x -m')
    parser.add_argument("evtx", type=str,
        help='Path to the EVTX event log file')
    parser.add_argument("-n", "--NoHeader", default=False, action="store_true",
        help="Do not print Header")
    parser.add_argument('-x','--Exclude', type = lambda s: re.split('[ ,;]', s), 
        help="strings in a comma separated word list ( -x 4624,4634)")
    parser.add_argument('-i', '--Include', type = lambda s: re.split('[ ,;]', s),
        help="only strings in a comma separated word list ( -i 4672,-500,04:55:07)")
    parser.add_argument('-m', '--Matchall', 
        type = lambda s: re.split('[ ,;]', s),
        help="all strings in a comma separated word list ( -m admin,,cmd.exe)")
        
    args = parser.parse_args()

    excludes = (args.Exclude)
    includes = (args.Include)
    matches = (args.Matchall)

    if not args.NoHeader:
        print(RDP_Header)
        
    with open(args.evtx, 'r') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0,
                                          access=mmap.ACCESS_READ)) as buf:
            fh = FileHeader(buf, 0x0)
            for xml, record in evtx_file_xml_view(fh):
                soup = BeautifulSoup(xml, "lxml")
                Date = soup.event.system.timecreated['systemtime']
                Date = Date[:-7]
                EventID = int(soup.event.system.eventid.string)
                Computer = soup.event.system.computer.string               
                if EventID in RDP_local_IDs:
                    event_info = "%s,%s,%s,%s," % (Date,EventID,RDP_local_IDs[EventID],Computer)
 
                    user_data = []
                    for info in RDP_info:
                        if soup.userdata.eventxml.find_all(info):
                            for tag in soup.find_all(info):
                                tag_text = (tag.text)
                        else:
                            tag_text = ''
                            
                        user_data.append(tag_text)

                    output = ((event_info) + ','.join(map(str,user_data)))                   
                    
                    if len(sys.argv) == 2:
                        print(output)

                    if args.NoHeader:
                        if len(sys.argv) == 3:
                            print(output)                   

                    if args.Matchall:
                        if all(match in output.casefold() for match in matches):
                            if args.Exclude:
                                if not any(exclude in output.casefold() for exclude in excludes):
                                    print(output)
                            else:
                                print(output)
                    elif args.Include:
                        if any(include in output.casefold() for include in includes):
                            if args.Exclude:
                                if not any(exclude in output.casefold() for exclude in excludes):
                                    print(output)
                            else:
                                print(output)
                    elif args.Exclude:
                        if not args.Include:
                            if not args.Matchall:
                                if not any(exclude in output.casefold() for exclude in excludes):
                                    print(output)

if __name__ == "__main__":
    main()