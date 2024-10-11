import os
import csv
import argparse
import subprocess
import re
import json
import sys

def extract_ip_addresses_from_json(json_file, search_eventid):
    ip_addresses = set()  # Use a set to store unique IP addresses

    # Updated regex to match valid IPv4 addresses
    ip_regex = re.compile(r'(?<!\d)(?<!\d\.)\b(?:[1-9]\d{0,2}|1\d{0,2}|2[0-4]\d|25[0-5])\.(?:[0-9]{1,3}\.){2}(?:[0-9]{1,3})(?!\.\d)(?!\d)')
    event_id_regex = re.compile(r'"EventID"\s*:\s*(\d+)')

    def is_valid_ipv4(ip):
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit() or not 0 <= int(part) <= 255:
                return False
        return True

    def find_ips_in_dict(d, log_name, event_id):
        for key, value in d.items():
            if isinstance(value, str):
                ips = ip_regex.findall(value)
                for ip in ips:
                    # Exclude IPs that start or end with a period
                    if is_valid_ipv4(ip) and not (ip.startswith('.') or ip.endswith('.')):
                        ip_addresses.add((ip, event_id, log_name, key, value))
            elif isinstance(value, dict):
                find_ips_in_dict(value, log_name, event_id)

    with open(json_file, 'r') as file:
        for line in file:
            try:
                event_id = "No EventID"
                if search_eventid:
                    # Search for EventID in the JSON string
                    event_id_match = event_id_regex.search(line)
                    event_id = event_id_match.group(1) if event_id_match else "No EventID"

                event = json.loads(line)
                find_ips_in_dict(event, os.path.basename(json_file), event_id)  # Use only the filename
            except json.JSONDecodeError:
                # Suppress JSON decoding errors
                continue

    return ip_addresses

def get_geolocation(ip):
    try:
        result = subprocess.run(['geoiplookup', ip], capture_output=True, text=True)
        if result.returncode == 0:
            output = result.stdout
            if "IP Address not found" in output:
                return "Non-Internet"
            if "GeoIP Country Edition" in output:
                parts = output.split(':')
                if len(parts) > 1:
                    country_info = parts[1].strip()
                    country_parts = country_info.split(',')
                    if len(country_parts) > 1:
                        country_code = country_parts[0].strip()
                        country_name = country_parts[1].strip()
                        return f"{country_code} {country_name}"
        return "-"  # Return a dash if no valid country code is found
    except Exception:
        return "-"  # Return a dash in case of an error

def process_json_file(json_file, search_eventid):
    ip_addresses = extract_ip_addresses_from_json(json_file, search_eventid)
    results = []
    for ip, event_id, log_name, field_name, field_content in ip_addresses:
        # Exclude IPs that start with 100, 127, 239, or 224
        if ip.startswith(('100.', '127.', '239.', '224.')):
            continue
        # Combine field name and content, and remove line breaks
        field_info = f"{field_name}: {field_content}".replace('\n', ' ').replace('\r', ' ')
        # Skip rows where "version" is in the "Field_Info"
        if "version" in field_info.lower():
            continue
        country = get_geolocation(ip)
        # Prepare the result based on whether EventID is included
        if search_eventid:
            result = [ip, country, event_id, log_name, field_info]
        else:
            result = [ip, country, log_name, field_info]
        # Replace commas with semicolons in all fields
        result = [field.replace(',', ';') for field in result]
        results.append(result)
    return results

def main():
    parser = argparse.ArgumentParser(description='Extract unique IP addresses from JSON logs.')
    parser.add_argument('-f', '--file', help='Single JSON or JSONL file to process')
    parser.add_argument('-d', '--directory', help='Directory of JSON or JSONL files to process')
    parser.add_argument('-e', '--eventid', action='store_true', help='Include search for EventID')
    args = parser.parse_args()

    all_results = []

    if args.file:
        all_results.extend(process_json_file(args.file, args.eventid))
    elif args.directory:
        for filename in os.listdir(args.directory):
            if filename.endswith('.json') or filename.endswith('.jsonl'):
                all_results.extend(process_json_file(os.path.join(args.directory, filename), args.eventid))
    else:
        print("Please provide a JSON file or directory to process.")
        return

    if all_results:
        # Use csv.writer to write to sys.stdout
        csv_writer = csv.writer(sys.stdout)
        # Write the header row based on whether EventID is included
        if args.eventid:
            csv_writer.writerow(['IP Address', 'Country', 'EventID', 'Event Log Name', 'Field_Info'])
        else:
            csv_writer.writerow(['IP Address', 'Country', 'Event Log Name', 'Field_Info'])
        # Write all results
        csv_writer.writerows(all_results)

if __name__ == "__main__":
    main()
