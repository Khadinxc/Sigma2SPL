![Update Sigma Rules](https://github.com/Khadinxc/Sigma2SPL/actions/workflows/update-sigma-rules.yml/badge.svg)
![GitHub last commit](https://img.shields.io/github/last-commit/Khadinxc/Sigma2SPL)
# Sigma2SPL - Automated Updates
Sigma Queries turned into SPL for Splunk Enterprise and Enterprise Security using pysigma - Automated [pysigma-backend-SPL-backend](https://github.com/SigmaHQ/pySigma-backend-splunk)

__Disclaimer: Not all of these rules have been validated either to ensure SPL is functional or if they are an exact replica of the Sigma rule. The script was created with the assumption that the pySigma Splunk backend does what it is meant to do.__

```
├───Splunk
│   ├───rules
│   ├───rules-compliance
│   ├───rules-emerging-threats
│   ├───rules-placeholder
│   └───rules-threat-hunting
```

## How do I use the helper to do this locally or in a Detection as Code pipeline?

I've included a pip freeze of required libraries and as per standard practice for Python development I suggest creating a virtual environment not to _break_ system wide package management. 

### Run the following commands to get started:

**Clone the sigma rules repository:**

```
git clone https://github.com/SigmaHQ/sigma.git
```

```
python -m venv .venv
```

**With Windows:**
```
.\.venv\Scripts\Activate.ps1
```

**With Linux**
```
./.venv/bin/activate
```
**Once in your Python virtual env:**

```
pip install -r requirements.txt
```

**Then you can use the script like this:**

```
..\.venv\Scripts\python.exe .\helper.py --sigma-dir "C:/Users/Kaiber/sigma" --output-dir "C:/Users/Kaiber/Sigma2SPL-2025/Splunk"
```

### Sample Rule Summary:

```
rules-threat-hunting Summary:
    Successful: 129
    Failed: 1
    Folders covered: 26

================================================================================
OVERALL CONVERSION COMPLETE!
================================================================================
Total files processed: 3646
Total successful conversions: 3631
Total failed conversions: 15

Output base directory: D:\Projects\Sigma2SPL\Splunk

Folder structure created:
    rules/
    rules-emerging-threats/
    rules-threat-hunting/
```

### Sample Rule:

**Sigma Rule:**
```
title: 7Zip Compressing Dump Files
id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
related:
    - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
      type: derived
status: test
description: Detects execution of 7z in order to compress a file with a ".dmp"/".dump" extension, which could be a step in a process of dump file exfiltration.
references:
    - https://thedfirreport.com/2022/09/26/bumblebee-round-two/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-27
modified: 2023-09-12
tags:
    - attack.collection
    - attack.t1560.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Description|contains: '7-Zip'
        - Image|endswith:
              - '\7z.exe'
              - '\7zr.exe'
              - '\7za.exe'
        - OriginalFileName:
              - '7z.exe'
              - '7za.exe'
    selection_extension:
        CommandLine|contains:
            - '.dmp'
            - '.dump'
            - '.hdmp'
    condition: all of selection_*
falsepositives:
    - Legitimate use of 7z with a command line in which ".dmp" or ".dump" appears accidentally
    - Legitimate use of 7z to compress WER ".dmp" files for troubleshooting
level: medium
```

**SPL Rule:**
```
# Title: 7Zip Compressing Dump Files
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-09-27
# Level: medium
# Description: Detects execution of 7z in order to compress a file with a ".dmp"/".dump" extension, which could be a step in a process of dump file exfiltration.
# MITRE Tactic: Collection
# Tags: attack.collection, attack.t1560.001
# False Positives:
#   - Legitimate use of 7z with a command line in which ".dmp" or ".dump" appears accidentally
#   - Legitimate use of 7z to compress WER ".dmp" files for troubleshooting

index=main sourcetype=WinEventLog:ProcessCreation (
    (CommandLine="*.dmp" OR CommandLine="*.dump" OR CommandLine="*.hdmp") AND (
        Description="7-Zip" OR Image="*\\7z.exe" OR Image="*\\7zr.exe" OR Image="*\\7za.exe" OR OriginalFileName="7z.exe" OR OriginalFileName="7za.exe"
    )
)
```

