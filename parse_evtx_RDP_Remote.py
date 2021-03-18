#! /usr/bin/env python3
# Find specific Events associated with RDP connections
# by parsing the following Windows event logs:
# This script parses:
# Microsoft-Windows-TerminalServices-RemoteConnectionManager.evtx
#
# Other Windows Event Logs with RDP Information:
# Microsoft-Windows-TerminalServices-LocalSessionManager/Operational.evtx
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

RDP_remote_IDs = {
261: 'RDP-TCP received a connection', 
1149: 'RDP Login screen accessed',
1006: 'Large Number of Connection Attempts' 
}

#None Values included for field concatenation  
RDP_info = ('param1',
'param3',
'none',
'none',
'none',
'none',
'none',
'none',
'param2'
)

# Event header contains values for other EVTX files for concatenation
RDP_Header = 'Date,EventID,Description,Computer,User,IP Address,'\
'Session,Sessionid,Source,TargetSession,Reason,ListenerName,Domain'

event_info_names = ('Date',
'EventID',
'Description',
'Computer'
)

def main():
    parser = argparse.ArgumentParser(description=
        "Find RDP Logon Events in Windows evtx files and output CSV",
        usage='parse_evtx_RDP.py evtx-file -n -i -x -m -h')
    parser.add_argument("evtx", type=str,
        help='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational.EVTX')
    parser.add_argument("-n", "--NoHeader", default=False, action="store_true",
        help="Do not print Header")
    parser.add_argument('-x','--Exclude', type = lambda s: re.split('[ ,;]', s), 
        help="strings in a comma separated word list ( -x 261,LOCAL)")
    parser.add_argument('-i', '--Include', type = lambda s: re.split('[ ,;]', s),
        help="only strings in a comma separated word list ( -i 1149,-500,04:55:07)")
    parser.add_argument('-m', '--Matchall', 
        type = lambda s: re.split('[ ,;]', s),
        help="all strings in a comma separated word list ( -m admin)")
        
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
                if EventID in RDP_remote_IDs:
                    event_info = "%s,%s,%s,%s," % (Date,EventID,RDP_remote_IDs[EventID],Computer)
 
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

'''#! /usr/bin/env python3
# Find specific Events associated with Microsoft
# Windows Backgroud Intelligent Transfer Service
# 
# This script parses the following Windows Event log:
# Microsoft-Windows-Bits-Client/Operational.evtx
#
# Requires Python-evtx https://github.com/williballenthin/python-evtx
# and BeautifulSoup

import sys
import re
import mmap
import contextlib

import argparse
from bs4 import BeautifulSoup, element

from Evtx.Evtx import FileHeader
from Evtx.Views import evtx_file_xml_view

bits_ids = {3: 'Bits Service Created a new job',
 4: 'Bits job completed',
 5: 'Bits job cancelled',
 59: 'Bits transfer initiated',
 60: 'Bits transfer terminated',
}

bits_data = ('string',
'string1',
'string2',
'user',
'jobtitle',
'jobid',
'jobowner',
'filecount',
'transferid',
'name',
'id',
'url',
'filetime',
'filength',
'bytestotal',
'bytestransferred',
'bytestransferredfrompeer'
)

# Event header contains values for other EVTX files for concatenation
Bits_Header = 'Date,EventID,Description,Computer,User,IP Address,'\
'string','string1','string2','user','jobtitle','jobid','jobowner',\
'filecount','transferid','name','id','url','filetime','filength',\
'bytestotal','bytestransferred','bytestransferredfrompeer'

def main():
    parser = argparse.ArgumentParser(description=
        "Find and Extract Windows Bits Events and output CSV",
        usage='parse_evtx_RDP.py evtx-file -n -i -x -m -a')
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
    parser.add_argument("-a", "--All", default=False, action="store_true",
        help="Print All Events from evtx file")
        
    args = parser.parse_args()

    excludes = (args.Exclude)
    includes = (args.Include)
    matches = (args.Matchall)

    if not args.NoHeader:
        print(Bits_Header)
        
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
                for EventID in bits_ids:
                    event_info = "%s,%s,%s,%s," % (Date,EventID,bits_ids[EventID],Computer)
 
                event_data = []
                for value in bits_data:
                    if soup.eventdata.find_all(value):
                        for tag in soup.find_all(value):
                            tag_text = (tag.text)
                    else:
                        tag_text = ''
                        #print(soup)
                        
                    event_data.append(tag_text)

                output = ((event_info) + ','.join(map(str,event_data)))                   
                    
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