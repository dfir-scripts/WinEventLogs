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
   rankdir=LR" |tee $temp_dot
   
   events=$(cat $INPUT_PATH|grep -E \,21\,R\|\,25\,R,\,24\,R| sed 's/\\/\\\\/g'|awk -F',' '{print $8","$9","$5","$4"\n"}'|sort -u)
   events1=$(printf %s"\n" $events|awk -F',' '{print "\"User: "$1"\\nIP/Host: "$2"\" -> \""$3"\\nComputer:\\n"$4"\""}')
   events2=$(printf %s"\n" $events1 | sed 's/\"2[1-5]/\"Logon or Reconnect\/Disconnect/')
   echo $events2 |tee -a $temp_dot
   echo "}" |tee -a $temp_dot
   dot -Tpng $temp_dot -o $OUTPUT_PATH
   echo $events
}

# Create a graphviz chart of RDP connection from parse_evtx_RDP.py output
[ -f "$1" ] || echo "USAGE: $0 <output file from parse_evtx_RDP.py> <png output file name>" 
[ -f "$1" ] || exit
INPUT_PATH=$1
OUTPUT_PATH=$2
[ "$2" != "" ] && OUTPUT_PATH=$2 ||OUTPUT_PATH="rdp.png"
 create_dot
