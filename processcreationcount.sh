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

cat $1 | jq -r '.Event|select(.System.EventID == 4688)|.EventData.NewProcessName'|sort|uniq -c|sort -rn
