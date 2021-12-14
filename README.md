# CVE-2021-44228 a.k.a. LOG4J
This is a public repository from Wortell containing information, links, files and other items related to CVE-2021-44228.

## 1. Scanning

Here are a few options to try and find applications that use Log4j and could potentially be abused:

* BURP Pro add-in:
https://gist.github.com/kugg/0d08b6548db249eaffaca1799e0d01d6

* File scanner (obv Powershell, voor Windows):
https://gist.github.com/Skons/0b9bbfbbf37d2707ccf83f3d549a6588

* File Scanner (obv Go, alle platformen)
https://github.com/dtact/divd-2021-00038--log4j-scanner
(Will also disable JNDI, when found!)

* Vulnerable test app:
https://github.com/kugg/log4shellverify

* Web/URL scanner:
https://github.com/zerobs-rvn/hrafna

* Web/URL scanner:
https://github.com/fullhunt/log4j-scan

* Shodan:
https://www.shodan.io/search?query=has_vuln%3ACVE2021-44228

* Tenable plugins:
https://www.tenable.com/plugins/search?q=cves%3A%28%22CVE-2021-44228%22%29&sort=&page=1

## 2. Indicators of Compromise

* NCC Group Indicators of compromise
https://research.nccgroup.com/2021/12/12/log4shell-reconnaissance-and-post-exploitation-network-detection/