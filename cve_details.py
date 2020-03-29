import bs4
import requests
from colorama import *
from termcolor import colored
import sys
banner = '''
                          __     __        _ __
  ______   _____     ____/ /__  / /_____ _(_) /____
 / ___/ | / / _ \   / __  / _ \/ __/ __ `/ / / ___/
/ /__ | |/ /  __/  / /_/ /  __/ /_/ /_/ / / (__  )
\___/ |___/\___/   \__,_/\___/\__/\__,_/_/_/____/ '''
print(colored(banner,'yellow'))
banner2 = '''
+-+-+-+-+-+-+ +-+-+-+ +-+-+-+ +-+-+ +-+-+-+-+-+-+ +-+-+ +-+-+-+-+-+-+-+-+
|S|e|a|r|c|h| |f|o|r| |C|V|E| |b|y| |n|u|m|b|e|r| |o|r| |k|e|y|w|o|r|d|s|
+-+-+-+-+-+-+ +-+-+-+ +-+-+-+ +-+-+ +-+-+-+-+-+-+ +-+-+ +-+-+-+-+-+-+-+-+'''
print(colored(banner2,"blue"))
print(colored("[+] By Romeos","green"))
cve = input(f"{Fore.BLUE}[{Fore.RED}*{Fore.BLUE}]{Fore.GREEN}Enter CVE keyword eg Apache, CVE-1999-1237 :{Fore.RED}")
url = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="+cve
headers = {
    "User-agent":"Mozilla/5.1"
}
print(f"{Fore.BLUE}[{Fore.RED}*{Fore.BLUE}]{Fore.GREEN}Searching for {cve} ...")
try:
    response = requests.get(url, headers = headers)
    soup = bs4.BeautifulSoup(response.text, 'html.parser')
    finding = soup.find_all("td", attrs = {"valign":"top"})
except KeyboardInterrupt:
    print(colored("[!] Exiting...","red"))
    sys.exit()
except Exception as e:
    print(e)
    sys.exit()
x = 0
y = 1
while x<=len(finding):
    #print(len(finding))
    try:
        print(f"{Fore.RED}{finding[x].get_text()} {Fore.GREEN}: {Fore.YELLOW}{finding[x+1].get_text()}")
        x+=2

    except:
        import sys
        sys.exit()
        pass
