#! /usr/bin/env python3
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

bits_data = ('Name',
'User',
'jobTitle',
'url',
'fileTime',
'fileLength',
'bytesTotal',
'bytesTransferred',
'bytesTransferredFromPeer',
'jobId',
'jobOwner',
'fileCount',
'String',
'String1'
)

# Event header contains values for other EVTX files for concatenation
Bits_Header = 'Date,EventID,Description,Computer,ProcessID,ThreadID,Name,'\
'User,jobTitle,URL,fileTime,fileLength,bytesTotal,bytesTransferred,'\
'bytesTransferredFromPeer,jobId,jobOwner,fileCount,String,String1'

def main():
    parser = argparse.ArgumentParser(description=
        "Find and Extract Windows Bits Events and output CSV",
        usage='parse_evtx_BITS.py evtx-file -n -i -x -m')
    parser.add_argument("evtx", type=str,
        help='Microsoft-Windows-Bits-Client%4Operational.evtx ')
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
                ProcessID = soup.event.system.execution['processid']
                ThreadID = soup.event.system.execution['threadid']                
                if EventID in bits_ids:
                    event_info = "%s,%s,%s,%s,%s,%s," % (Date,EventID,bits_ids[EventID],Computer,ProcessID,ThreadID)

                    try:

                        event_data = {}
                        for child in soup.eventdata.children:
                            if type(child) is element.Tag:
                                val = child.text.replace(',', ';')
                                event_data[child['name']] = ' '.join(val.split())

                        event_data_result = []
                        for value in bits_data:
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
