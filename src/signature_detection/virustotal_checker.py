import ipaddress
import requests


class VirusTotalChecker:
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.malicious_results = []
        self.benign_results = []

    def check_ip(self, ip_address: ipaddress.IPv4Address) -> bool:

        # check cached results before making API request
        if str(ip_address) in self.malicious_results:
            return True
        if str(ip_address) in self.benign_results:
            return False
        response = requests.get(f'https://www.virustotal.com/api/v3/ip_addresses/{str(ip_address)}',
                                headers={'x-apikey': self.api_key}).json()
        if not response:
            raise Exception('Virustotal API Request failed')
        results = response['data']['attributes']['last_analysis_stats']
        is_malicious = results['malicious'] > 0 or results['suspicious'] > 0
        if is_malicious:
            self.malicious_results.append(str(ip_address))
        else:
            self.benign_results.append(str(ip_address))
        return is_malicious
