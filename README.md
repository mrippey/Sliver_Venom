# Sliver_Venom

Sliver C2 Framework is a great Red Team tool that happens to be used by malicious actors periodically. 
By using JARM hash matches and hardcoded HTTP Headers found in Sliver's source code, malicious C2's can 
possibly be identified.

## Usage

Sliver_Venom supports the following:

```bash
sliver_venom.py -h
Examples:
         python3 sliver_venom.py -i 1.2.3.4
         python3 sliver_venom.py -s

optional arguments:
  -h, --help                 show this help message and exit
  -i, --ipaddr               Single IP address to look for JARM hash matches
  -s, --shodan_q             Shodan query for default Sliver C2 HTTP Headers
