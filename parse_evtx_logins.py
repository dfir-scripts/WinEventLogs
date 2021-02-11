#! /usr/bin/env python3
# Extract Common Windows Logins Events and field from the Security.evtx log file
# 
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

evtxs = {1102: 'Log Cleared',
4624: 'User logon',
4625: 'Login Failed',
4634: 'Logoff',
4647: 'User Initiated logoff',
4648: 'Attempted Login by a process',
4672: 'Administrator Logon',
4740: 'Account Locked out',
4776: 'NTLM Credential Auth',
4778: 'Reconnect(RDP or FastUser Switch)', 
4770: 'Kerberos Ticket Renewed',
4771: 'Kerberos pre-auth failed',
4768: 'Kerberos TGT Requested',
4769: 'Kerberos service ticket requested',
4779: 'Disconnect(RDP or FastUser Switch)',
4825: 'RDP Connection Denied',
4985: 'State of a Transaction Changed'
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

def main():
    parser = argparse.ArgumentParser(description=
        "Extract Windows Account Logon Events to CSV",
        usage='parse_evtx_logins.py Security.evtx -n -i -x -m')
    parser.add_argument("evtx", type=str,
        help='Path to the Windows Security EVTX event log file')
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

    header = (','.join(map(str,event_info_names + event_data_names)))
    if not args.NoHeader:
        print(header)
        
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
                if EventID in evtxs:
                    event_info = "%s,%s,%s,%s," % (Date,EventID,evtxs[EventID],Computer)

                    try:
                        event_data = {}
                        for child in soup.eventdata.children:
                            if type(child) is element.Tag:
                                event_data[child['name']] = ' '.join(child.text.split())
                        event_data_result = []
                        for value in event_data_names:
                            result = event_data.get(value)
                            if result is None:
                                result = ''
                            event_data_result.append(result)
                    except:
                        pass
                        
                    output = ((event_info) + ','.join(map(str,event_data_result)))
                    
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
