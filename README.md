# CVE-2021-44228 a.k.a. LOG4J
This is a public repository from Wortell containing information, links, files and other items related to CVE-2021-44228.

![log4j-wortell-octo-ninja](https://user-images.githubusercontent.com/24291535/146188101-431b057d-43ef-4a75-8aba-f03e50e87d8a.png)


## 1. Scanning

Here are a few options to try and find applications that use Log4j and could potentially be abused:

* BURP Pro add-in:
https://gist.github.com/kugg/0d08b6548db249eaffaca1799e0d01d6
* File scanner (obv Powershell, for Windows):
https://gist.github.com/Skons/0b9bbfbbf37d2707ccf83f3d549a6588
* File Scanner (obv Go, all platforms)
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
* Lunasec Scanner:
https://github.com/lunasec-io/lunasec/releases/tag/v1.0.0-log4shell 
* Log Scanner (It checks local log files for indicators of exploitation attempts)
https://github.com/Neo23x0/log4shell-detector
* Detects log4j versions on your file-system, including deeply recursively nested copies (jars inside jars inside jars). Works on Linux, Windows, and Mac, and everywhere else Java runs, too!
https://github.com/mergebase/log4j-detector

## 2. Indicators of Compromise

* NCC Group Indicators of compromise
https://research.nccgroup.com/2021/12/12/log4shell-reconnaissance-and-post-exploitation-network-detection/
* Nested Log4J exploit strings
https://github.com/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words 
* Microsoft's Threat Intelligence Center IOC feed
https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Log4j_IOC_List.csv

## 3. Vulerable Applications

* (dutch) NCSC list of vulnerable applications:
https://github.com/NCSC-NL/log4shell/blob/main/scanning/README.md

## 4. Information

* Lunasec (Guide to detect and mitigate Log4Shell)
https://www.lunasec.io/docs/blog/log4j-zero-day-mitigation-guide/
* Govcert.ch Zero Day Exployst targeting popular Java Library Log4j
https://www.govcert.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/
* Dutch NCSC guidance:
https://www.ncsc.nl/actueel/nieuws/2021/december/12/kwetsbare-log4j-applicaties-en-te-nemen-stappen
* Log4Shell: the defender’s worst nightmare?
https://www.sekoia.io/en/log4shell-the-defenders-worst-nightmare/
* Microsoft: Guidance for preventing, detecting, and hunting for CVE-2021-44228 Log4j 2 exploitation 
https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/
* How to detect Log4j with MS Endpoint Manager (Alex Verboon)
https://www.verboon.info/2021/12/how-to-detect-the-log4shell-vulnerability-cve-2021-44228-with-microsoft-endpoint-configuration-manager/

![anatomy_log4j](https://user-images.githubusercontent.com/16960513/146193236-e405dcc9-c2d6-40d0-b7ff-3d0317cc6afb.png)

## 5. Samples

* VX-underground is maintaining a library of samples from malware families that have been seen abusing the log4j cve: https://samples.vx-underground.org/samples/Families/Log4J%20Malware/

* Samples of log4j library versions to help validate log4j scanners / detectors: https://github.com/mergebase/log4j-samples/

* Microsoft Sentinel provides a CVE-2021-44228 Log4Shell Research Lab Environment for testing and learning more about the vulnerability: https://github.com/Cyb3rWard0g/log4jshell-lab

## 6. Patches

* Apache LOG4J version 2.16.0
https://logging.apache.org/log4j/2.x/download.html

## 7. Mitigation Guide
**! IMPORTANT !** Exploits are continously developed. Aways make sure to work with the **latest** version of scanners.

1. Identify potential vulnerable devices by using https://github.com/NCSC-NL/log4shell/blob/main/software/README.md - This a time consuming task, but you need to do it anyway, so better start quickly!

2. Run a scan to check for vulnerable java applications/dependancies using: https://github.com/mergebase/log4j-detector with command `java log4j-detector-2021.12.14.jar c:/` and watch for files that have been classified as vulnerable.

![image](https://user-images.githubusercontent.com/24291535/146075945-037eb767-afd8-4612-8284-49f16b80b8b5.png)

3. Run a scan to check for expoit attempts using https://github.com/Neo23x0/log4shell-detector `python3 log4shell-detector.py -p c:\` and wath for exploitation attempts.

![image](https://user-images.githubusercontent.com/24291535/146076166-4276bcf6-7366-40a9-bf15-f9ace0d35c2e.png)

 ## 8. Wortell blogs

 Here are Wortell specialists blogging about LOG4J:

 * Jeffrey Appel: Microsoft Defender
https://jeffreyappel.nl/microsoft-defender-for-endpoint-log4j/

![tvm](https://user-images.githubusercontent.com/16960513/146193334-6e6198cf-2a06-4950-a681-d9f5db8b7f6e.png)

 * Jeroen Niesen: reverse engineering
 https://www.wortell.nl/en/blogs/cve-2021-44228-log4shell
  
![reverse_engineering](https://user-images.githubusercontent.com/16960513/146193357-1d38aad3-b7a3-45a9-9130-8f3880e3c804.png)
