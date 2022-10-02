#!/usr/bin/bash
#https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4625
#https://answers.microsoft.com/en-us/windows/forum/all/where-can-i-find-the-full-list-of-failure-reasons/d0269426-2183-4d99-8af0-cc009dee6658
#
function usage(){
  echo requires jq and jsonl export of Security.evtx
  echo "USAGE: $0 <Security.evtx.jsonl>"
  exit  
}  
which jq > /dev/null || usage
file $1 2>/dev/null | grep -q JSON || usage
[ "$1" == "-h" ] && usage
header="TIME,EVENTID,SUBJECTDOMAIN,SUBJECTUSER,TARGETDOMAIN,TARGETUSER,IPADDRESS,LOGONTYPE,AUTHPACKAGENAME,PROCESSNAME,FAILREASON,STATUS,SUBSTATUS"
result=$(cat $1 | jq -r '.Event|select(.System.EventID==4625 or .System.EventID==4771)|"\(.System.TimeCreated."#attributes".SystemTime),\(.System.EventID),\(.EventData.SubjectDomainName),\(.EventData.SubjectUserName),\(.EventData.TargetDomainName),\(.EventData.TargetUserName),\(.EventData.IPAddress),\(.EventData.LogonType),\(.EventData.AuthenticationPackageName),\(.EventData.ProcessName),\(.EventData.FailureReason),\(.EventData.Status),\(.EventData.SubStatus)"')

[ "${result}" ]  && echo "********************* LOGON FAILURE STATUS/SUBSTATUS CODES ********************* " 
[ "${result}" ]  && echo "
CODE,DESCRIPTION
0XC000005E,There are currently no logon servers available to service the logon request.
0XC0000064,user name does not exist
0XC000006A,user name is correct but the password is wrong
0XC000006D,This is either due to a bad username or authentication information
0XC000006E,Unknown user name or bad password.
0XC000006F,user tried to logon outside his day of week or time of day restrictions
0XC0000070,workstation restriction; or Authentication Policy Silo violation; look for EID 4820 on domain controller
0XC0000071,expired password
0XC0000072,account is currently disabled
0XC00000DC,Indicates the Sam Server was in the wrong state to perform the desired operation.
0XC0000133,clocks between DC and other computer too far out of sync
0Xc000015b,The user has not been granted the requested logon type (aka logon right) at this machine
0XC000018C,The logon request failed because the trust relationship between the primary domain and the trusted domain failed.
0XC0000192,An attempt was made to logon; but the netlogon service was not started.
0XC0000193,account expiration
0XC0000224,user is required to change password at next logon
0XC0000225,evidently a bug in Windows and not a risk
0XC0000234,user is currently locked out
0XC0000413,Logon Failure: The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine.
0X8009030E,No credentials are available in the security package"|column -t -s ","
echo " 

"
printf "%s\n%s"  ${header} "${result}"|column -t -s "," 
