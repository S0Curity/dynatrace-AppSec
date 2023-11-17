#!/bin/python

import os
import requests
import json
import configparser
import argparse
from datetime import datetime, timedelta
from syslog_rfc5424_parser import SyslogMessage
import socket

def read_properties_file(file_path):
    config = configparser.ConfigParser()
    config.read(file_path)
    return config

def get_last_pull_time():
    # Read the last pull time from a file
    filename = "last_pull_time.txt"
    if os.path.exists(filename):
        with open(filename, "r") as file:
            last_pull_time_str = file.read()
            if last_pull_time_str:
                return datetime.fromisoformat(last_pull_time_str)
    else:
        return datetime.utcnow() - timedelta(hours=24)

    # Return a default time (e.g., 24 hours ago) if no last pull time is found
    return datetime.utcnow() - timedelta(hours=24)

def save_last_pull_time(last_pull_time):
    # Save the last pull time to a file
    filename = "last_pull_time.txt"
    with open(filename, "w") as file:
        file.write(last_pull_time)

def get_dynatrace_vulnerabilities(api_token, base_url, last_pull_time, syslog_server, syslog_port):
    # Dynatrace API endpoint for vulnerabilities
    vulnerabilities_url = f"{base_url}/api/v2/securityProblems"

    # Set up headers with the API token
    headers = {
        "Authorization": f"Api-Token {api_token}",
        "Content-Type": "application/json",
    }
    print(last_pull_time)
    # Set the parameters to filter vulnerabilities based on last_pull_time
    params = {
        "from": last_pull_time,
        "fields": "+riskAssessment,+managementZones,+codeLevelVulnerabilityDetails,+globalCounts",
    }

    try:
        #print(requests.url)
        #print(requests.body)
        # Make a GET request to the vulnerabilities endpoint with parameters
        response = requests.get(vulnerabilities_url, headers=headers, params=params)

#        print(response.request.url)
#        print(response.request.params)
#        print(response.json())
        
        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Parse the JSON response
            vulnerabilities = response.json()
            securityProbs = vulnerabilities.get("securityProblems", [])
            # Print or process the vulnerabilities data as needed
            for vulnerability in securityProbs:
#                print(vulnerability)
                forward_to_syslog_server(syslog_server, syslog_port, vulnerability)

            # Update the last pull time to the current time
            save_last_pull_time(datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3])

        else:
            print(f"Failed to retrieve vulnerabilities. Status code: {response.status_code}")

    except Exception as e:
        print(f"An error occurred: {e}")

def forward_to_syslog_server(syslog_server, syslog_port, log):
    try:
        # Create a TCP socket connection to the syslog server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((syslog_server, int(syslog_port)))

            # Send the message to the syslog server
#            log = log.encode('UTF-8')
            s.sendall(str(log).encode('utf-8'))

#        print(f"Message forwarded to syslog server: {log}")

    except Exception as e:
        print(f"Exception: {e}")


def main():
    file_name = "config.properties"
    props = read_properties_file(file_name)
#    print(props)
    api_token = props.get("DEFAULT", "api_key")
    base_url = props.get("DEFAULT", "base_url")
    timezone = props.get("DEFAULT", "timezone")
    syslog_server = props.get("DEFAULT", "syslog_server")
    syslog_port = props.get("DEFAULT", "syslog_port")
    
    # Get the last pull time from the file
    last_pull_time = get_last_pull_time()
    last_pull_time = last_pull_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + timezone

    # Get vulnerabilities from Dynatrace based on last pull time
    get_dynatrace_vulnerabilities(api_token, base_url, last_pull_time, syslog_server, syslog_port)

if __name__ == "__main__":
    main()