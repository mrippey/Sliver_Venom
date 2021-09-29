import argparse
import asyncio
from dotenv import load_dotenv
from jarm.scanner.scanner import Scanner
import os 
import shodan


jarm_hashes = ('28d28d28d00028d00043d28d28d43d47390d982d099a542ccbc90628951062',
            '2ad2ad0002ad2ad00043d2ad2ad43da5207249a18099be84ef3c8811adc883',
            '2ad2ad00000000000043d2ad2ad43dc4b09cccb7c1d19522df9b67bf57f4fb')


def search_jarm_hashes(target, port=443):

    result = asyncio.run(Scanner.scan_async(target, port))

    for jarm_hash in result:
        if jarm_hash in jarm_hashes:
            print(f'Hash: {jarm_hash} matched your query!')
        else:
            print("""The server you are looking for may not yet a have a JARM hash.
            Try a Shodan search...""") 


def shodan_query_default_headers():

    load_dotenv()

    SHODAN_API = os.getenv('SHODAN_API_KEY')

    api = shodan.Shodan(SHODAN_API)

    shodan_query = '"HTTP/1.1 404 Not Found" "Cache-Control: no-store, no-cache, must-revalidate" "Content-Type: application/octet-stream" "X-Powered-By: PHP/" "Server: Apache/"'

    try:
        shodan_results = api.search(shodan_query)

        print(f'Results returned: {shodan_results["total"]}')
        print()

        for idx, shodan_output in enumerate(shodan_results['matches'][:], start=1):
            print(f'{idx}. IP Address: {shodan_output["ip_str"]}')
                     
    except shodan.APIError as err:
        print(f'Error: {err}')

  
def main():

    menu = r"""

 (`-').->           _           (`-') (`-')  _   (`-')                (`-') (`-')  _<-. (`-')_            <-. (`-')  
 ( OO)_     <-.    (_)         _(OO ) ( OO).-/<-.(OO )               _(OO ) ( OO).-/   \( OO) )     .->      \(OO )_ 
(_)--\_)  ,--. )   ,-(`-'),--.(_/,-.\(,------.,------,)         ,--.(_/,-.\(,------.,--./ ,--/ (`-')----. ,--./  ,-.)
/    _ /  |  (`-') | ( OO)\   \ / (_/ |  .---'|   /`. '         \   \ / (_/ |  .---'|   \ |  | ( OO).-.  '|   `.'   |
\_..`--.  |  |OO ) |  |  ) \   /   / (|  '--. |  |_.' |   (`-')  \   /   / (|  '--. |  . '|  |)( _) | |  ||  |'.'|  |
.-._)   \(|  '__ |(|  |_/ _ \     /_) |  .--' |  .   .'<-.(OO ) _ \     /_) |  .--' |  |\    |  \|  |)|  ||  |   |  |
\       / |     |' |  |'->\-'\   /    |  `---.|  |\  \ ,------.)\-'\   /    |  `---.|  | \   |   '  '-'  '|  |   |  |
 `-----'  `-----'  `--'       `-'     `------'`--' '--'`------'     `-'     `------'`--'  `--'    `-----' `--'   `--'

Sliver_Venom

Identify servers that may or may not be acting as Sliver command and control infrastructure. 
 
*** Run this script in a VM or behind a proxy as calls to unknown hosts will be made. *** 

Examples:
\t python sliver_venom.py -i IPADDRESS (single IP address)
\t python sliver_venom.py -s Shodan Query for Default Sliver C2 HTTP Headers

JARM Hashes: 
\t Default: 28d28d28d00028d00043d28d28d43d47390d982d099a542ccbc90628951062
\t Go V 1.16.7: 2ad2ad0002ad2ad00043d2ad2ad43da5207249a18099be84ef3c8811adc883
\t Go V 1.17: 2ad2ad00000000000043d2ad2ad43dc4b09cccb7c1d19522df9b67bf57f4fb
"""

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=menu,
    )
    parser.add_argument("-i", "--ipaddr", help="Name of group to lookup")
    parser.add_argument("-s", "--shodan_token", help="Return all records")

    args = parser.parse_args()

    if args.ipaddr:
        try:
            print(menu)
            search_jarm_hashes(args.ipaddr)
        except Exception as err:
            print(err)
    elif args.shodan_token:
        print(menu)
        shodan_query_default_headers(args.shodan_token)  
    else:
        print(menu)


if __name__ == "__main__":
    main()
