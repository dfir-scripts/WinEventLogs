#!/usr/bin/bash
#
function usage(){
  echo requires jq and jsonl export of Microsoft-Windows-TaskScheduler%4Operational.evtx
  echo "USAGE: $0 <Security.evtx.jsonl>"
  exit
}
which jq > /dev/null || usage
file $1 2>/dev/null | grep -q JSON || usage
[ "$1" == "-h" ] && usage
title="WINDOWS TASK SCHEDULER SUMMARY"
header="COUNT,EVENTID,RESULT,TASKNAME"
result=$(cat $1 | jq -r '.Event|select(.System.EventID == 102 or .System.EventID == 201 or .System.EventID == 202 or .System.EventID == 101 or .System.EventID == 200 or .System.EventID == 140 or .System.EventID == 141)|",\(.System.EventID),\(.EventData."#attributes".Name),\(.EventData.TaskName)"'|sort|uniq -c|sort -rn|sed 's/ ,/,/')
[ '$result' == '' ] || echo $title && \
printf "%s\n%s"  "${header}" "${result}"|column -t -s ","
