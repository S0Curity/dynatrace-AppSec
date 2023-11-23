# Dynatrace to Syslog

This script is used to read Dynatrace AppSec detections and forward to any external destinations as syslog.

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install required dependencies.

```bash
pip install json, configparser, argparser, socket, requests, os
```

## Usage

1. Edit config.properties file and add necessary details.
2. generate api_key with necessary permissions to read RVA, RAP details.
3. timezone parameter must be in exact "+01:00" format
4. Add cron entry to run the script in a set interval. No command line parameters required during execution.
