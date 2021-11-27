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
        usage='parse_evtx_BITS.py Microsoft-Windows-Bits-Client%4Operational.evtx -n')
    parser.add_argument("evtx", type=str,
        help='Microsoft-Windows-Bits-Client%4Operational.evtx ')
    parser.add_argument("-n", "--NoHeader", default=False, action="store_true",
        help="Do not print Header")

        
    args = parser.parse_args()

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
                            output = ((event_info) + ','.join(map(str,event_data_result)))                   
                            print(output)           
                    except:
                        pass

if __name__ == "__main__":
    main()
