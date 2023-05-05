#!/bin/bash
# https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/

function usage(){
  echo "$0 
  
  requires jq and a jsonl export of Security.evtx
  USAGE,$0 <Security.evtx.jsonl> -r
      Optional
        -r Print raw csv without header"
  exit  
}  
which jq > /dev/null || usage
file $1 2>/dev/null | grep -q JSON || usage
[ "$1" == "-h" ] && usage

header="COUNT,PID,PPID,SUBJECT_LOGON_ID,COMPUTER"
result="$(cat $1 | jq -r '.Event|select(.System.EventID == 4688)|",\(.EventData.NewProcessName),\(.EventData.ParentProcessName),\(.EventData.SubjectLogonId),\(.System.Computer)"'| sort |uniq -c|sort -rn)"

[ "$2" != "-r" ] &&  printf "%s\n%s"  "${header}" "${result}"|column -t -s "," || printf "%s\n%s" "${result}" | sed 's/ ,/,/g'
