#!/usr/bin/bash
#
function usage(){
  echo requires jq and jsonl export of Security.evtx
  echo "USAGE: $0 <Security.evtx.jsonl>"
  exit  
}  
which jq > /dev/null || usage
file $1 2>/dev/null | grep -q JSON || usage
[ "$1" == "-h" ] && usage
echo File Name: $1
echo  "Count,LoginType,EventID,SubjectUserName,TargetUserName,IPAddress,Process Name"
cat $1 | jq -r '.Event|select(.EventData.LogonType != null)|"\(.EventData.LogonType),\(.System.EventID),\(.EventData.AuthenticationPackageName),\(.EventData.SubjectUserName),\(.EventData.TargetUserName),\(.EventData.IPAddress),\(.EventData.ProcessName)"' |\
sort|uniq -c|sort -rn


echo "


LogonType  Description: Example
0          System account: System startup
2          Interactive: User login from local console
3          Network: RDP NLA and mapped network drive
4          Batch Job: Scheduled task, AT command
5          Service: Used to run a service and accounts with alternate creds Telnet, FTP
6          Proxy: 
7          Unlock: Unlock a password protected screen saver
8          Network Clear Text Logon: IIS Basic Authentication
9          NewCredentials: RunAs or mapping a network drive with alternate credentials
10         RemoteInteractive: Terminal Services, Remote Desktop or Remote Assistance.
11         CachedInteractive: Logon cached domain credentials (disconnected from domain)
12         CashedRemoteInteractive: Logon using remote system away from the network DC
13         CashedUnlock: Unlock that occurs when the remote system is away from the network DC.

"
