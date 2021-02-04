#! /usr/bin/env python3
# Extract Common Windows Scheduled Tasks Events from
# Microsoft-Windows-TaskScheduler4Operational.evtx to CSV
# Requires Python-evtx https://github.com/williballenthin/python-evtx
# and BeautifulSoup

import mmap
import contextlib

import argparse
from bs4 import BeautifulSoup, element

from Evtx.Evtx import FileHeader
from Evtx.Views import evtx_file_xml_view

evtx_ids = {102,106,110,140,141,142,145,200,201,202,319}
header = 'Date,EventID,EventDataName,ProcessID,ThreadID,ActionName,'\
      'TaskName,UserName,UserContext,Command,Path,Priority,ResultCode,'\
      'TaskInstanceID,ProcessID,CurrentQuota,ErrorDescription'

event_data_names = ('ActionName',
'TaskName',
'UserName',
'UserContext',
'Command',
'Path',
'Priority',
'ResultCode',
'TaskInstanceID',
'ProcessID',
'CurrentQuota',
'ErrorDescription')

def main():
    parser = argparse.ArgumentParser(
        description="Extract Common Windows Scheduled Tasks Events to CSV")
    parser.add_argument("WinEventLog", type=str,
        help="Path to Microsoft-Windows-TaskScheduler4Operational.evtx")
    args = parser.parse_args()
    with open(args.WinEventLog, 'r') as f:
        print(header)
        with contextlib.closing(mmap.mmap(f.fileno(), 0,
                access=mmap.ACCESS_READ)) as buf:
            fh = FileHeader(buf, 0x0)
            for xml, record in evtx_file_xml_view(fh):
                soup = BeautifulSoup(xml, "lxml")
                Date = soup.event.system.timecreated['systemtime']
                Date = Date[:-7]
                EventID = int(soup.event.system.eventid.string)
                ProcessID = soup.event.system.execution['processid']
                ThreadID = soup.event.system.execution['threadid']
                EventDataName = soup.eventdata['name']
                Keywords = soup.event.system.keywords.string
                if EventID:
                    event_info = "%s,%s,%s,%s,%s," % \
                        (Date,
                        EventID,
                        EventDataName,
                        ProcessID,
                        ThreadID)
 
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
                        
                    print((event_info) + ','.join(map(str,event_data_result)))

if __name__ == "__main__":
    main()
