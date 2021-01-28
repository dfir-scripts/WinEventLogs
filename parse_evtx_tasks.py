#! /usr/bin/env python3
# Extract Common Windows Scheduled Tasks Events from
# Microsoft-Windows-TaskScheduler4Operational.evtx to CSV
# Based on gist by Y0ug https://gist.github.com/y0ug/bd7b2c94943afac276f9
# Requires Python-evtx https://github.com/williballenthin/python-evtx
# and BeautifulSoup

import mmap
import contextlib

import argparse
from bs4 import BeautifulSoup, element

from Evtx.Evtx import FileHeader
from Evtx.Views import evtx_file_xml_view

evtx_ids = {102,106,110,140,141,142,145,200,201,202,319}
header = 'Date,EventID,EventDataName,ProcessID,ThreadID,Keywords,'\
      'ActionName,TaskName,UserName,UserContext,Command,Path,Priority,'\
      'ResultCode,TaskInstanceID,ProcessID,CurrentQuota,ErrorDescription'

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
                EventID = int(soup.event.system.eventid.string)
                ProcessID = soup.event.system.execution['processid']
                ThreadID = soup.event.system.execution['threadid']
                EventDataName = soup.eventdata['name']
                Keywords = soup.event.system.keywords.string
                event_info = "%s,%s,%s,%s,%s,%s," % \
                    (Date,
                    EventID,
                    EventDataName,
                    ProcessID,
                    ThreadID,
                    Keywords)
                
                event_data = {}
                for child in soup.eventdata.children:
                    if type(child) is element.Tag:
                        event_data[child['name']] = ' '.join(child.text.split())
                        ActionName = event_data.get('ActionName')
                        TaskName = event_data.get('TaskName')
                        UserName = event_data.get('UserName')
                        UserContext = event_data.get('UserContext')
                        Command = event_data.get('Command')
                        Path = event_data.get('Path')
                        Priority = event_data.get('Priority')
                        ResultCode = event_data.get('ResultCode')
                        TaskInstanceID = event_data.get('TaskInstanceId')
                        ProcessID = event_data.get('ProcessID')
                        CurrentQuota = event_data.get('CurrentQuota')                        
                        ErrorDescription = event_data.get('ErrorDescription')
                        
                        event_data_values = "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % \
                        (ActionName,
                        TaskName,
                        UserName,
                        UserContext,
                        Command,
                        Path,
                        Priority,
                        ResultCode,
                        TaskInstanceID,
                        ProcessID,
                        CurrentQuota,
                        ErrorDescription)
                        
                        print(event_info + event_data_values)
                        
if __name__ == "__main__":
    main()