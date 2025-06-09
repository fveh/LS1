class ProxyResolver:
    """Resolve proxies using DNS over HTTPS to avoid detection"""
    def __init__(self, dns_server="https://cloudflare-dns.com/dns-query"):
        self.dns_server = dns_server

    def resolve_proxies(self, domain):
        import requests
        headers = {'Accept': 'application/dns-json'}
        params = {'name': domain, 'type': 'A'}
        try:
            response = requests.get(self.dns_server, params=params, headers=headers)
            data = response.json()
            return [answer['data'] for answer in data.get('Answer', []) if answer['type'] == 1]
        except:
            return []
