import ipaddress
import requests


class VirusTotalChecker:
    def __init__(self, api_key: str = None):
        # TODO:find default val for api key DONT COMMIT
        self.api_key = api_key or 'ac4a0a1ceb16a26b6ec68c85e81b6f9321541fef18f521f5a0d92aa98ab4711f'

    def check_ip(self, ip_address: ipaddress.IPv4Address) -> bool:
        response = requests.get(f'https://www.virustotal.com/api/v3/ip_addresses/{str(ip_address)}',
                                headers={'x-apikey': self.api_key}).json()
        if not response:
            raise Exception
        results = response['data']['attributes']['last_analysis_stats']
        return results['malicious'] > 0 or results['suspicious'] > 0
