import json
import csv
import sys
from collections import Counter
import argparse

def process_event(event):
    system = event.get('System', {})
    event_data = event.get('EventData', {})
    system_attributes = system.get('TimeCreated', {}).get('#attributes', {})
    system_execution_attributes = system.get('Execution', {}).get('#attributes', {})
    provider_attributes = system.get('Provider', {}).get('#attributes', {})
    security_attributes = system.get('Security', {}).get('#attributes', {})

    if not args.summarize:
        return (
            system_attributes.get('SystemTime'),
            event_data.get('#attributes', {}).get('Name'),
            event_data.get('Path'),
            event_data.get('Priority'),
            event_data.get('ProcessID'),
            event_data.get('TaskName'),
            system.get('Channel'),
            system.get('Computer'),
            system.get('Correlation'),
            system.get('EventID'),
            system.get('EventRecordID'),
            system_execution_attributes.get('ProcessID'),
            system_execution_attributes.get('ThreadID'),
            system.get('Keywords'),
            system.get('Level'),
            system.get('Opcode'),
            provider_attributes.get('Guid'),
            provider_attributes.get('Name'),
            security_attributes.get('UserID'),
            system.get('Task'),
            system.get('Version'),
        )
    else:
        return (
            event_data.get('#attributes', {}).get('Name'),
            event_data.get('TaskName'),
            event_data.get('Path'),
            system.get('Computer'),
            system.get('Level'),
            provider_attributes.get('Name'),
            security_attributes.get('UserID'),
        )
    
# Set up command line arguments
parser = argparse.ArgumentParser()
parser.add_argument('-s', '--summarize', action='store_true', help='Stack and summarize similar tasks')
parser.add_argument('filename', help='Convert JSONL to CSV Microsoft-Windows-TaskScheduler/Operational.evtx.jsonl')
args = parser.parse_args()

# Initialize counter
counter = Counter()

# Set up CSV writer
writer = csv.writer(sys.stdout)

if not args.summarize:
    headers = [
        'SystemTime',
        'Event',
        'Path',
        'Priority',
        'ProcessID',
        'TaskName',
        'Channel',
        'Computer',
        'Correlation',
        'EventID',
        'EventRecordID',
        'Execution_ProcessID',
        'Execution_ThreadID',
        'Keywords',
        'Level',
        'Opcode',
        'Provider_Guid',
        'Provider_Name',
        'Security_UserID',
        'Task',
        'Version',
    ]
    writer.writerow(headers)

# Read JSONL data
with open(args.filename) as jsonl_file:
    for line in jsonl_file:
        data = json.loads(line)
        event = data.get('Event', {})
        result = process_event(event)
        if result is not None:
            if args.summarize:
                counter.update([str(result)])
            else:
                writer.writerow(result)

if args.summarize:
    headers = ['Count'] + [
        'Event',
        'TaskName',
        'Path',
        'Computer',
        'Level',
        'Provider_Name',
        'Security_UserID',
    ]
    writer.writerow(headers)
    for entry, count in counter.most_common():
        writer.writerow([count] + list(eval(entry)))
