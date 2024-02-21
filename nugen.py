import yaml
import sys
import requests
import argparse
import configparser
import os

from help_text import SYNTAX_HELP


def create_yaml_file(data):
    with open('output.yaml', 'w') as file:
        yaml.dump(data, file, default_flow_style=False)


def parse_data(cve_id, author_name):
    nist_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?apiKey=07365be7-a957-4a64-949f-0d7d6a9c67a1&cveId={cve_id}"
    epss_api_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"

    nist_response = requests.get(nist_url)
    epss_response = requests.get(epss_api_url)
    if nist_response.status_code != 200:
        print(f"Failed to get data from NIST for {cve_id}")
        sys.exit(1)
    elif epss_response.status_code != 200:
        print(f"Failed to get data from EPSS for {cve_id}")
        print(epss_response.text)
        sys.exit(1)
    else:
        nist_data = nist_response.json()
        epss_data = epss_response.json()['data'][0]

        cve_vuln_data = nist_data['vulnerabilities'][0]['cve']
        cvss_Data = cve_vuln_data['metrics']['cvssMetricV31'][0]['cvssData']

        data = {
            'id': cve_id,
            'info': {
                'name': cve_id,
                'author': author_name,
                'severity': cvss_Data['baseSeverity'],
                'description': cve_vuln_data['descriptions'][0]['value'],
                'remediation': '',  # You can add remediation details here if available
                'reference': [url['url'] for url in cve_vuln_data['references']]
            },
            'classification': {
                'cvss-metrics': cvss_Data['vectorString'],
                'cvss-score': cvss_Data['baseScore'],
                'cve-id': cve_id,
                'cwe-id': cve_vuln_data['weaknesses'][1]['description'][0]['value'],
                'epss-score': epss_data['epss'],
                'epss-percentile': epss_data['percentile'],
                'cpe': cve_vuln_data['configurations'][0]['nodes'][0]['cpeMatch'][0]['criteria']
            },
            'metadata': {
                'verified': True,
                'max-request': 1,
                'vendor': 'pyload',
                'product': 'pyload',
                'shodan-query': 'html:"pyload"',
                'zoomeye-query': 'app:"pyLoad"'
            },
            'tags': ['cve', f'cve{cve_id}', 'pip', 'pyload', 'access-control']
        }

        return data


def parse_arguments():
    parser = argparse.ArgumentParser(description=SYNTAX_HELP,formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-id', '--cve-id', dest="cve_id", type=str, help='CVE ID', action='store', required=False , nargs='?')
    parser.add_argument('-a', '--author', dest="author", type=str, help='Author', action='store', required=False, nargs='?')
    parser.add_argument('--config', dest="config", type=str, help='API Key Configuration file', action='store', required=False, nargs='?')
    return parser.parse_args()
    
        
def create_config_file(key_value):
    config = configparser.ConfigParser()
    
    if os.path.exists('./config.ini'):
        print("Config file already exists")
        print("Do you want to overwrite it? (y/n) : ", end = "")
        response = input().lower()
        if response == 'n':
            print("Exiting...")
            sys.exit(0)
        elif response != 'y':
            print("Invalid response")
            print("Exiting...")
            sys.exit(0)
    
    config['DEFAULT'] = {'api_key': key_value}
    with open('config.ini', 'w') as configfile:
        config.write(configfile)
    
    sys.exit(0)


def check_args(args):
    if args.cve_id is None or args.author is None:
        if args.cve_id is None:
            print("CVE ID is missing")
            sys.exit(1)
        if args.author is None:
            print("Author is missing")
            sys.exit(1)
        if args.cve_id is None and args.author is None:
            if args.cve_id is None:
                print("CVE_ID and Author are missing")
                sys.exit(1)
                
def main():
    try:
        config = configparser.ConfigParser()
        config.read('config.ini')
        api_key = config['DEFAULT']['api_key']
    except :
        print("Config file not found")
        print("Please create a config file using --config option")
    args = parse_arguments()
    
    if args.config:
        create_config_file(args.config)
        
    CVE_ID = args.cve_id
    author = args.author
    

    data = parse_data(CVE_ID, author)
    create_yaml_file(data)



if __name__ == "__main__":
    main()
