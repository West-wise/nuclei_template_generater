import yaml
import sys
import requests
import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(description='Vulnerability Data Generator')
    parser.add_argument('CVE_ID', type=str, help='CVE ID')
    parser.add_argument('author', type=str, help='Author')
    return parser.parse_args()


def create_yaml_file():
    data = {
        'id': 'CVE-2024-21644',
        'info': {
            'name': 'pyLoad Flask Config - Access Control',
            'author': 'West-wise',
            'severity': 'high',
            'description': '''
                pyLoad is the free and open-source Download Manager written in pure Python. 
                Any unauthenticated user can browse to a specific URL to expose the Flask config, 
                including the `SECRET_KEY` variable. 
                This issue has been patched in version 0.5.0b3.dev77.
            ''',
            'remediation': '''
                Apply the latest security patches or updates provided by the vendor 
                to mitigate this vulnerability.
            ''',
            'reference': [
                'https://github.com/advisories/GHSA-mqpq-2p68-46fv',
                'https://github.com/fkie-cad/nvd-json-data-feeds',
                'https://nvd.nist.gov/vuln/detail/CVE-2024-21644'
            ]
        },
        'classification': {
            'cvss-metrics': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            'cvss-score': 7.5,
            'cve-id': 'CVE-2024-21644',
            'cwe-id': 'CWE-284',
            'epss-score': 0.00186,
            'epss-percentile': 0.56007,
            'cpe': 'cpe:2.3:a:pyload:pyload:*:*:*:*:*:*:*:*'
        },
        'metadata': {
            'verified': True,
            'max-request': 1,
            'vendor': 'pyload',
            'product': 'pyload',
            'shodan-query': 'html:"pyload"',
            'zoomeye-query': 'app:"pyLoad"'
        },
        'tags': ['cve', 'cve2024', 'python', 'pip', 'pyload', 'access-control']
    }

    with open('output.yaml', 'w') as file:
        yaml.dump(data, file, default_flow_style=False)

# 생성된 데이터를 YAML 파일로 저장

def parse_data(cve_id, author_name):
    
    nist_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    epss_api_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    
    nist_response = requests.get(nist_url)
    epss_response = requests.get(epss_api_url)
    if nist_response.status_code != 200 :
        print(f"Failed to get data from NIST for {cve_id}")
        sys.exit(1)
    elif epss_response.status_code != 200:
        print(f"Failed to get data from EPSS for {cve_id}")
        sys.exit(1)
    else:
        nist_data = nist_response.json()
        epss_data = epss_response.json()['data'][0]

        cve_vuln_data = nist_data['vulnerabilities'][0]['cve']
        cvss_Data = cve_vuln_data['metrics']['cvssMetricV31'][0]['cvssData']
        
        name = cve_id
        author = author_name
        severity = cvss_Data['baseSeverity']
        description = cve_vuln_data['descriptions'][0]['value']
        reference = [url['url'] for url in cve_vuln_data['references']]
        
        cvss_metrics: cvss_Data['vectorString']
        cvss_score = cvss_Data['baseScore']
        cve_id_in_classification : cve_id
        cwe_id = cve_vuln_data['weaknesses'][1]['description'][0]['value']
        epss_score = epss_data['epss']
        epss_percentile = epss_data['percentile']
        cpe = cve_vuln_data['configurations'][0]['nodes'][0]['cpeMatch'][0]['criteria']

    
def main():
    args = parse_arguments()
    CVE_ID = args.CVE_ID
    author = args.author

    parse_data(CVE_ID,author)
    # 사용자가 제공하는 값으로 데이터 생성
    create_yaml_file()
if __name__ == "__main__":
    main()