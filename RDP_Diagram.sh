#!/bin/bash

function create_dot(){
 # cleanup and create a new DOT temp file to hold  RDP output
 rm /tmp/tmp*.dot 2>/dev/null
 temp_dot=$(mktemp -u).dot
 touch $temp_dot
 # Write parameters to $temp_dot
   echo "strict digraph rdp{
   fontname=\"Helvetica,Arial,sans-serif\"
   node [fontname=\"Helvetica,Arial,sans-serif\"]
   edge [fontname=\"Helvetica,Arial,sans-serif\"]
   node [shape=box];
   node [color = \"blue\"]
   rankdir=LR" > $temp_dot

   events=$(printf %s"\n"  "$filename"|grep -E \,21\,R\|\,22\,R\|\,24\,R\|\,25\,R | sed 's/\\/\\\\/g'|awk -F',' '{print $8","$9","$5","$4"\n"}'|sort -u)
   events=$(printf %s"\n" $events|awk -F',' '{print "\"User: "$1"\\nIP/Host: "$2"\" -> \""$3"\\nComputer:\\n"$4"\""}')
   events=$(printf %s"\n" $events | sed 's/\"2[1-5]/\"Logon or Reconnect\/Disconnect/')
   echo "$events" >> $temp_dot
   echo "}" >> $temp_dot
   dot -Tpng $temp_dot -o $output && echo $output" created"
}

function usage(){
echo "Create a png image of RDP connections
USAGE: $0 -f <output file from parse_evtx_RDP.py>
REQUIRES: Results file from parse_evtx_RDP.py
          (https://github.com/dfir-scripts/WinEventLogs/blob/master/parse_evtx_RDP.py)
OPTIONAL:
  -o <png output file name>
     Set output file name (default name rdp.png)
  -s <search term(s)>
     Narrow results by adding a comma separated list search terms
  -h <Displays this help file>

  EXAMPLE 1:
  Extract RDP Events to a graphviz image file named rdp-logins.png
    $0 -f parse_evtx_RDP-combined.csv -o rdp-logins.png
  EXAMPLE 2:
  Search for RDPs from Jan 12, 2023 at 11PM to Jan 13, 9:59 AM.
    $0 -f RDP-combined.csv -o suspect-RDP-time.png -s \"2023-01-12 23:\",\"2023-01-13 0\"
  EXAMPLE 3:
  Search for RDPs from user admin or IP address.
    $0 -f RDP-combined.csv -o suspect-RDP-user-IP.png -s admin,192.168.23.14
  " && exit
}

while getopts f:o:s:h flag
do
    case "${flag}" in
        f) filename=${OPTARG};;
        o) output=${OPTARG};;
        s) search=${OPTARG};;
        h) usage && exit;;
    esac
done

# Create a graphviz chart of RDP connection from parse_evtx_RDP.py output
[ "$output" ] ||output="rdp.png"
[ "$search" ] && search=$(echo "$search"|sed 's/\,/\\\|/g')
[ "$search" ] || search="."
[ "$filename" ] || usage
filename=$(cat "$filename" |grep "$search")
[ "$filename" ] && create_dot || usage
