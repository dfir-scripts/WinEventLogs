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
header="COUNT,LOGONTYPE,EVENTID,AUTHPACKAGE,SUBJECTUSERNAME,TARGETUSERNAME,IPADDRESS,PROCESSNAME,LOGONPROCESSNAME"
result=$(cat $1 | jq -r '.Event|select(.EventData.LogonType != null)|",\(.EventData.LogonType),\(.System.EventID),\(.EventData.AuthenticationPackageName),\(.EventData.SubjectUserName),\(.EventData.TargetUserName),\(.EventData.IPAddress),\(.EventData.ProcessName),\(.EventData.LogonProcessName)"' |\sort|uniq -c|sort -rn|sed 's/^ *//g')
printf "%s\n%s"  ${header} "${result}"|column -t -s ","

legend="LOGON,,
TYPE,DESCRIPTION,EXAMPLE
0,System account,System startup
2,Interactive,User login from local console
3,Network,RDP NLA and mapped network drive
4,Batch Job,Scheduled task; AT command
5,Service,Used to run a service and accounts with alternate creds Telnet;FTP
6,Proxy 
7,Unlock,Unlock a password protected screen saver
8,Network Clear Text Logon,IIS Basic Authentication
9,NewCredentials,RunAs or mapping a network drive with alternate credentials
10,RemoteInteractive,Terminal Services; Remote Desktop or Remote Assistance.
11,CachedInteractive,Logon cached domain credentials (disconnected from domain)
12,CashedRemoteInteractive,Logon using remote system away from the network DC
13,CashedUnlock,unlock that occurs when the remote system is away from the network DC."
echo " 
************ Logon Types Legend ************
"
printf "%s\n%s"  "${legend}"|column -t -s ","
echo " 
********************************************
"
