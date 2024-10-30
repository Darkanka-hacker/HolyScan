# HolyScan

![holyscan-icon](https://github.com/user-attachments/assets/9cb6b069-264b-40fe-aafc-4c7d8cd117d8)

HolyScan is a network scanning tool with a variety of plugins for scanning services like SSH, FTP, WinRM, and more.


## Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/Darkanka-hacker/HolyScan.git
   ```
   ```bash
   cd HolyScan
   ```
2. install depenancies

   ```bash
   pip install -r requirements.txt
   ```
3. Start the scanner:
   ```bash
   python HolyScan.py
   ```

## Usage

1. Enter the target IP and click “Invoke Holy Scan” to start the process.


## What it does:

### FTP - Bruteforce usernames and passwords

### SSH - Bruteforce usernames and passwords submitted by the user, will automatcally prompt the user to start a ssh session if any user was found.

### HTTP - Automatically add domains and finds subdomains, directory scan on the IP or domain (will also scan any found subdomain)

### kerberos - Simple enumeration script

### LDAP - Basic scanning

### WINRM - Bruteforce usernames and passwords submitted by the user, will prompt in the scan results if with the connection command if any user was pwned

## Legal stuff

This script is designed solely for educational and authorized security testing purposes. Users are strictly prohibited from using this tool for any unauthorized or malicious activities, including but not limited to scanning or exploiting systems without the explicit permission of the system owner.

Legal Use Only: Ensure you have obtained full, written permission to scan and interact with any IP address or system targeted by this script. Unauthorized use may violate applicable laws and result in serious legal consequences.

By using this script, you agree to abide by these terms and accept full responsibility for any actions performed with it. The developers disclaim all liability for improper or unlawful use.
