#! /usr/bin/env python3
# Searches Windows event logs for RDP connection information
# 
# Targets the following logs for inbound and outbound connections:
# Microsoft-Windows-TerminalServices-LocalSessionManager/Operational.evtx
# Microsoft-Windows-TerminalServices-RemoteConnectionManager.evtx
# Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational.evtx 
# Microsoft-Windows-TerminalServices-RDPClient/Operational.evtx     

# https://www.13cubed.com/downloads/rdp_flowchart.pdf
# https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/
# Requires Python-evtx https://github.com/williballenthin/python-evtx

import os
import sys
import mmap
import contextlib
import textwrap

import argparse
from bs4 import BeautifulSoup, element

from Evtx.Evtx import FileHeader
from Evtx.Views import evtx_file_xml_view

RDP_IDs = {21: 'RDP Session logon success',
 22: 'RDP Shell start notification received',
 23: 'RDP Session logoff',
 24: 'RDP Session has been disconnected',
 25: 'RDP Session reconnection success',
 39: 'RDP Session <X> disconnected by session <Y>',
 40: 'RDP Session <X> disconnected reason code <Z>',
 1149: 'RDP Login screen accessed',
 1006: 'Large Number of Connection Attempts',
 98: 'RDP Successful Connection',
 131: 'RDP accepted a new TCP connection',
 140: 'RDP connection Failed IP x.x.x.x incorect password',
 1024: 'RDP is trying to connect to another host',
 1102: 'Client initiated an outbound RDP connection',
 1026: 'RDP client has been disconnected',
 1029: 'Base64(sha256(UserName))',
 1105: 'Multi-transport connection disconnected'
}

RDP_local_info = ('none',
'user',
'address',
'sessionid',
)

RDP_remote_info = ('param2',
'param1',
'param3',
'none',
)

Evtx_Logs = [
"Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx", 
"Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx", 
"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx", 
"Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx")

# Event header contains values for other EVTX files for concatenation
RDP_Header = 'Date,Channel,RecordID,Computer,EventID,Description,Domain,User,' \
'Host/IP Address,Session,Direction'

def parse_evtx(evtx_file):
    with open(evtx_file, 'r') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0,
                                          access=mmap.ACCESS_READ)) as buf:
            fh = FileHeader(buf, 0x0)
            for xml, record in evtx_file_xml_view(fh):
                soup = BeautifulSoup(xml, "lxml")
                Date = soup.event.system.timecreated['systemtime']
                Date = Date[:-7]
                EventID = int(soup.event.system.eventid.string)
                Computer = soup.event.system.computer.string
                Channel = soup.event.system.channel.string
                RecordID = soup.event.system.eventrecordid.string 
                if EventID in RDP_IDs:
                    event_info = "%s,%s,%s,%s,%s,%s," % (Date,Channel,RecordID,Computer,EventID,RDP_IDs[EventID])
                    # Find a process each EVTX log file
                    user_data = []
                    if Channel == "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational":
                        for info in RDP_local_info:
                            if soup.userdata.eventxml.find_all(info):
                                for tag in soup.find_all(info):
                                    tag_text = (tag.text)
                            else:
                                tag_text = ''
                            
                            user_data.append(tag_text)
                        output = ((event_info) + ','.join(map(str,user_data)))
                        if not ",LOCAL," in output:
                            print(output + ",RDP<-in")
                    ############################        
                    if Channel == "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational":
                        for info in RDP_remote_info:
                            if soup.userdata.eventxml.find_all(info):
                                for tag in soup.find_all(info):
                                    tag_text = (tag.text)
                            else:
                                tag_text = ''
                            user_data.append(tag_text)
                            output = ((event_info) + ','.join(map(str,user_data)))
                            print(output + "RDP<-in") 
                    ############################
                    if Channel == "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational":
                        tag_exists = soup.eventdata.find
                        if not tag_exists:
                            user_data.append(",,,,")
                        else:
                            for child in soup.eventdata.children:
                                if type(child) is element.Tag:
                                    if (child['name']) == 'ClientIP':
                                        IP = (child.text)
                                    else:
                                        IP = ''
                                    if (child['name']) == 'ConnType':
                                        Port = (child.text)
                                    else:
                                        Port = ''
                            user_data.append(",," + IP + Port + ",")
                            output = ((event_info) + ','.join(map(str,user_data)))
                            print(output + "RDP<-in")
                    ############################
                    if Channel == "Microsoft-Windows-TerminalServices-RDPClient/Operational":
                        user = ''
                        IP = ''               
                        for child in soup.eventdata.children:
                            if type(child) is element.Tag:
                                if (child['name']) == 'TraceMessage':
                                    User = (child.text).rstrip("-")
                                if (child['name']) == 'Server Name':
                                    IP = (child.text)
                                if (child['name']) == 'Value':
                                    IP = (child.text)
                                    if IP.isnumeric():
                                        IP = ''
                        user_data.append(",," + IP + Port + ",")
                        output = ((event_info) + ','.join(map(str,user_data)))
                        print(output + "RDP<-in")

def main():
    parser= argparse.ArgumentParser(
    prog= 'parse_evtx_RDP.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
            Searches these Windows RDP Event Logs for connection information:
                Microsoft-Windows-TerminalServices-LocalSessionManager/Operational.evtx
                Microsoft-Windows-TerminalServices-RemoteConnectionManager.evtx
                Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational.evtx 
                Microsoft-Windows-TerminalServices-RDPClient/Operational.evtx'''))
    parser.add_argument('Evtx_Source', help="Windows event log file or directory")
    parser.add_argument("-n", "--NoHeader", default=False, action="store_true",
        help="Do not print Header")
    args = parser.parse_args()

    if not args.NoHeader:
        print(RDP_Header)

    #Enumerate and verify files in directory path, then send to parser
    if (os.path.isdir(args.Evtx_Source)):
        for evt_log in Evtx_Logs:
            file_to_parse = os.path.join(args.Evtx_Source, evt_log)
            if os.path.isfile(file_to_parse):
               parse_evtx(file_to_parse)

    #Enumerate and verify file in input string, then send to parser
    elif os.path.isfile(args.Evtx_Source):
        if  args.Evtx_Source.lower().endswith('evtx'):
            file_to_parse = args.Evtx_Source
            parse_evtx(file_to_parse)
    else:
        print("invalid path!!") 


if __name__ == "__main__":
    main()