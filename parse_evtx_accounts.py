#! /usr/bin/env python3
# Extract Common Windows Account Change Events and Fields
# from the Security.evtx log file
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
4704: 'User Right Assigned', 
4720: 'New User Account Created', 
4722: 'New User Account Enabled', 
4725: 'User Account Disabled',
4726: 'User Account Deleted',
4728: 'Member Added to Global Group,' 
4731: 'Security enabled Group Created,' 
4732: 'Member Added to local Group,' 
4733: 'Account removed from Local Sec. Group,' 
4765: 'SID History added to Account,'
4634: 'Local Group Deleted,' 
4735: 'Local Group Changed,' 
4740: 'Account Locked out,'
4748: 'Local Group Deleted,'
4756: 'Member Added to Universal Group,' 
4766: 'SID History add attempted on Account,' 
4767: 'User Account Unlocked,'
4781: 'Account Name Changed,'
4793: 'Password Policy Checking API called' 
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
