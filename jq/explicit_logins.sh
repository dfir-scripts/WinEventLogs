#!/usr/bin/bash
#https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4648
#
function usage(){
  echo requires jq and jsonl export of Security.evtx
  echo "USAGE: $0 <Security.evtx.jsonl>"
  exit  
}  
which jq > /dev/null || usage
file $1 2>/dev/null | grep -q JSON || usage
[ "$1" == "-h" ] && usage
header="TIME,EVENTID,SUBJECTDOMAIN,SUBJECTUSER,TARGETDOMAIN,TARGETUSER,IPADDRESS,PROCESSNAME,PID,THREADID,LOGONGUID"
result=$(cat $1 | jq -r '.Event|select(.System.EventID==4648)|"\(.System.TimeCreated."#attributes".SystemTime),\(.System.EventID),\(.EventData.SubjectDomainName),\(.EventData.SubjectUserName),\(.EventData.TargetDomainName),\(.EventData.TargetUserName),\(.EventData.IpAddress),\(.EventData.ProcessName),\(.System.Execution."#attributes".ProcessID),\(.System.Execution."#attributes".ThreadID),\(.EventData.LogonGuid)"')

printf "%s\n%s"  ${header} "${result}"|column -t -s "," 
