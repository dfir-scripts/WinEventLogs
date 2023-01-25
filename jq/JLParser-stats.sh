#!/usr/bin/bash
#
function usage(){
  echo requires jq and json export of JLParser.py in json format
  echo "USAGE: $0 <file.json>"
  exit
}

function JLParser-stats(){
    header="HITCOUNT,NAME,SIZE,LPATH"
    result=$(cat $input 2>/dev/null|jq -r '.[]|select(.Local_Path!="" and .Artifact=="LNK_File")|",\(.Source_Name),\(.FileSize),\(.Local_Path)"'|sort |uniq -c|sort -rn)
    [ "$result" ] && echo "Local LNK Summary"|column -t -s "," 
    [ "$result" ] && printf "%s\n%s"  ${header} "${result}"|column -t -s "," 
    echo "*********************************************************" 
  
    header="HITCOUNT,NAME,NETWORKSHARE,FLAGS"
    result=$(cat $input 2>/dev/null|jq -r '.[]|select((.Network_Share_Name!="" or .Network_Providers!="") and .Artifact=="LNK_File")|",\(.Source_Name),\(.Network_Share_Name),\(.Network_Share_Flags)"'|sort |uniq -c|sort -rn)
    [ "$result" ] && echo "Network LNK Summary"|column -t -s "," 
    [ "$result" ] && printf "%s\n%s"  ${header} "${result}"|column -t -s ","  && \
    echo "*********************************************************"  

    header="HITCOUNT;DATAFLAGS;NAME"
    result=$(cat $input 2>/dev/null |jq -r '.[]|select((.Data_Flags!=null and .FileSize!=0) and .Artifact=="LNK_File")|";\(.Data_Flags);\(.Source_Name)"'|sort |uniq -c)
    [ "$result" ] && echo "DataFlags"|column -t -s "," 
    [ "$result" ] && printf "%s\n%s"  ${header} "${result}"|column -t -s ";"  && \
    echo "*********************************************************"  
	
    header="HITCOUNT;DATAFLAGS;LOCALPATH"
    result=$(cat $input 2>/dev/null |jq -r '.[]|select((.ShowWindow!="SW_NORMAL") and .Artifact=="LNK_File")|";\(.ShowWindow);\(.Source_Name)"'|sort |uniq -c)
    [ "$result" ] && echo "Window Open"|column -t -s "," 
    [ "$result" ] && printf "%s\n%s"  ${header} "${result}"|column -t -s ";"
    echo "*********************************************************"      
    
    header="HITCOUNT,NAME,SIZE,LPATH"
    result=$(cat $input 2>/dev/null|jq -r '.[]|select(.Local_Path!="" and .Artifact!="LNK_File")|",\(.AppDesc),\(.FileSize),\(.Local_Path)"'|sort |uniq -c|sort -rn)
    [ "$result" ] && echo "Jump List Summary"|column -t -s "," 
    [ "$result" ] && printf "%s\n%s"  ${header} "${result}"|column -t -s "," 
    echo "*********************************************************"
    header="HITCOUNT,APPLICATION,NETWORKSHARE,FLAGS"
    result=$(cat $input 2>/dev/null|jq -r '.[]|select((.Network_Share_Name!="" or .Network_Providers!="") and .Artifact!="LNK_File")|",\(.AppDesc),\(.Network_Share_Name),\(.Network_Share_Flags)"'|sort |uniq -c|sort -rn)
    [ "$result" ] && echo "Network Jumplist Summary"|column -t -s "," 
    [ "$result" ] && printf "%s\n%s"  ${header} "${result}"|column -t -s ","  && \
    echo "*********************************************************" 
 
}
which jq > /dev/null || usage
file $1 2>/dev/null | grep -q JSON || usage
[ "$1" == "-h" ] && usage
input="$1"
JLParser-stats
