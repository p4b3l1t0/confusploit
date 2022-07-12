## This is an Script to find vulnerable servers to CVE-2022-26134 and can be used together SHODAN CLI and Bash Scripting One-Liner
#### Please use only for legal and educational purposes

Confluence Pre-Auth Remote Code Execution via OGNL Injection (CVE-2022-26134)

- On June 02, 2022 Atlassian released a security advisory for their Confluence Server and Data Center applications, highlighting a critical severity unauthenticated remote code execution vulnerability. The OGNL injection vulnerability allows an unauthenticated user to execute arbitrary code on a Confluence Server or Data Center instance.


### Installation

#### clone the repo:

	git clone https://github.com/p4b3l1t0/confusploit.git && cd confusploit

#### Install requirements:

	pip3 install -r requirements.txt 

#### give permissions:

	chmod +x confusploit.py

#### Execute and choose your best option:

	python3 confusploit.py

