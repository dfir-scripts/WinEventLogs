#!/usr/bin/bash
#
function usage(){
  echo requires jq and json export of JLParser.py in json format
  echo "USAGE: $0 <lnk_file.json>"
  exit
}
function jumplink_csv(){

  cat $input 2>/dev/null|jq -r '.[]|select(.Local_Path!="" or .Network_Share_Name!="" or .Network_Providers!="")|",\(.Source_Name),\(.FileSize),\(.Local_Path),\(.Artifact),\(.AppDesc),\(.Network_Share_Name),\(.Network_Share_Flags),\(.Data_Flags)"'|sort |uniq -c|sort -rn
}

which jq > /dev/null || usage
file $1 2>/dev/null | grep -qi JSON || usage
[ "$1" == "-h" ] && usage
input="$1"
echo "COUNT,NAME,SIZE,LOCAL_PATH,TYPE,DESCRIPTION,NETWORK_SHARE_NAME,NETWORK_FLAG,DATA_FLAGS"
jumplink_csv
