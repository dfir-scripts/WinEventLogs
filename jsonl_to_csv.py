import pandas as pd
import json
import argparse
import csv
import sys

# Create the parser and add the filename argument
parser = argparse.ArgumentParser()
parser.add_argument('filename', help='The name of the file to process')
args = parser.parse_args()

# Open the jsonl file and load data
with open(args.filename, 'r') as json_file:
    json_list = list(json_file)

# Convert json strings to dictionaries
json_data = [json.loads(jline) for jline in json_list]

# Normalize semi-structured JSON data into a flat table.
df = pd.json_normalize(json_data)

# Replace 'nan' values with '-'
df.fillna('-', inplace=True)

# Create a CSV writer that writes to the console
writer = csv.writer(sys.stdout)

# Write the header to the CSV
writer.writerow(df.columns)

# Write the rows to the CSV
for index, row in df.iterrows():
    writer.writerow(row)
