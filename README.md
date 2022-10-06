# pfSense RCE Tool for CVE-2021-41282
A tool for CTFs or Penetration Tests that can be used to help exploit [CVE-2021-41282](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41282) on pfSense routers running version <= 2.5.2. 

Payload based on the [PoC published by Shielder](https://www.shielder.com/advisories/pfsense-remote-command-execution/).

Known issues:
 - When sending a command to the pfSense router, the return key has to be pressed twice to get the output. This may get fixed later on. If anyone knows how to fix this please feel free to update the code.

## Instructions for use
 - Build using GCC compiler on Linux, not tested on Windows.
 - Help: ./pfsense_252_rce -h or --help
 - Usage: ./pfsense_252_rce \<target router> \<filename on target> \<listener ip> \<listener port>
 - Once the listener has started, in a browser visit the malicious page hosted on the pfSense router. You do not need to be authenticated on the pfSense router in order to do this. On successful callback you will be in a root shell on the pfSense router.

Note: If you do not have a payload on the pfSense router, the tool will generate the payload for you and provide deployment instructions. The listener will not start unless the malicious file is present. 



![image](https://user-images.githubusercontent.com/29107794/194351976-51b8b820-ccef-4671-8622-ca25db3ba4b4.png)

Fig 1: Example of payload generation


![image](https://user-images.githubusercontent.com/29107794/194351837-0b8d79e2-58f4-4611-bcae-055c83bd6c5f.png)

Fig 2: Example of successful interaction


Disclaimer: This tool has been developed for educational and testing purposes only. It must not be used in production environments unless explicit permission has been granted e.g. for penetration testing. Use of this tool suite is at your own risk, and I will not be held responsible for any damage or loss as a result of its use. If using this tool, always ensure you comply with local and international laws.
