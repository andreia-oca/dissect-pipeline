import os
import vt
from dotenv import load_dotenv

load_dotenv()

class VirusTotalClient:
    """
    A client for interacting with the VirusTotal API to check IP addresses and file hashes.
    This client requires an API key, which can be provided directly or set as an environment variable.
    """
    def __init__(self, api_key: str | None = None):
        """
        Initialize the VirusTotal client using the provided API key or from environment variable.
        """
        self.api_key = api_key or os.getenv("VT_API_KEY")
        if not self.api_key:
            raise ValueError("VirusTotal API key is required.")
        self.client = vt.Client(self.api_key)

    def check_ip(self, ip: str):
        """
        Check the reputation of an IP address using the VirusTotal API.
        """
        return self.client.get_object(f"/ip_addresses/{ip}")

    def check_hash(self, hash_value: str):
        """
        Check the reputation of a file hash using the VirusTotal API.
        """
        return self.client.get_object(f"/files/{hash_value}")

    def close(self):
        """
        Close the VirusTotal client connection.
        """
        self.client.close()
