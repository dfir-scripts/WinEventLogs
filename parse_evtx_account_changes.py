#! /usr/bin/env python3
# Extract Common Windows Account Change Events
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
4704: 'A User Right was Assigned',
4705: 'A User Right was Removed', 
4720: 'A New User Account Created', 
4722: 'A New User Account Enabled', 
4725: 'User Account Disabled',
4726: 'User Account Deleted',
4728: 'Member Added to Global Group', 
4731: 'A Security-enabled Group Created', 
4732: 'A Member was Added to Security-enabled Local Group', 
4733: 'An Account was removed from Local Security-enabled Group',
4734: 'A Security-enabled Local Group was Deleted', 
4740: 'Account Locked out',
4748: 'Local Group Deleted',
4756: 'Member Added to Universal Group',
4765: 'SID History added to Account',
4766: 'SID History add attempted on Account', 
4767: 'User Account Unlocked',
4781: 'Account Name Changed',
4793: 'Password Policy Checking API called',
4794: 'Attempted Admin Password Change! Directory Services Restore Mode(DSRM)',
4799: 'A security-enabled local group membership was enumerated' 
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
        "Extract Common Windows Account Change Events",
        usage='parse_evtx_account_changes.py Security.evtx -n')
    parser.add_argument("evtx", type=str,
        help='Security.evtx ')
    parser.add_argument("-n", "--NoHeader", default=False, action="store_true",
        help="Do not print Header")
      
    args = parser.parse_args()

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
                        output = ((event_info) + ','.join(map(str,event_data_result)))                   
                        print(output)  
                    except:
                        pass
                        
if __name__ == "__main__":
    main()