# Ultimate RedTeam Scenarios

**Why?**: Well if you have ever been in positions of management you are often asked "how much are we secured", "Provide justification for your hiring of extra resources", "At a given moment do you have the test results of xyz assets", etc. All these are difficult questions to answer for any manager or team member. Through years of testing and trying out strategies I have founded these scenarios which will help you provide a **Holistic** coverage for your entire company's infrastructure. By No Means this is an exhaustive list, but thats what we want to achieve, pick a product and create scenarios on how you would threat model it and red team it. Feel free to redact sensitive company data and contribute to this github repo. Whatever you do DUPLICATES are not allowed. 

**Disclaimer**:
Hey there! Before diving in, just a quick note to let you know that everything shared here is for informational purposes only. While the content is meant to be helpful and insightful, I'm not responsible for any actions you take based on this information. If you're planning to try anything risky, make sure you're on the right side of the law and have proper authorization.

Remember, security is a serious business. If you're not sure about something, always double-check or seek professional advice. By using this information, you agree that I can't be held liable for any damage, loss, or legal trouble that might come your way.

Stay safe, stay ethical, and happy exploring!

### Epic Repo: Ultimate DevSecOps Library: https://github.com/sottlmarek/DevSecOps

## Contribution rules
If you want to contribute to this library of knowledge please create proper PR (Pull Request) with description what you are adding following these set of rules: 

* Clear description of PR like (which Product, Scenario, why(relevance) )
* Keep it simple - Fill the description properly
* Fact over feelings or personal opinions (Have you tried it yourself?)
* Add source and follow the library style
* Avoid duplicits - one product, one scenario 
* Report typos as issue not via PR. 

# Contribution Format

Example: 
```
**Internal Network**
**Standard User Data Access Assessment**  {Github Username}

Investigate what sensitive information a standard user can access, focusing on potential data leaks or unauthorized access to confidential information.  
   - *Tool*: LinEnum  
   - *Description*: Run LinEnum for assessing what data and system functionalities are accessible with standard user privileges.
```

**RedTeam-Scenarios library info:** 

![stars](https://img.shields.io/github/stars/Ghostyboy0719/RedTeam-Scenarios?style=for-the-badge)
![watchers](https://img.shields.io/github/watchers/Ghostyboy0719/RedTeam_Scenarios?color=green&style=for-the-badge) 
![watchers](https://img.shields.io/github/forks/Ghostyboy0719/RedTeam_Scenarios?color=orange&style=for-the-badge)

# Table of Contents

- [Internal-Network](#internal-network)
- [Github](#github)
- [Active Directory](#active-directory)
- [Azure/Entra Active Directory](#azureentra-active-directory)
- [VPN](#vpn)
- [Printer Services](#printer-services)
- [Containers](#containers)
- [EDR Bypass](#edr-bypass)
- [Wireless Attacks](#wireless-attacks)
- [Database Attacks](#database-attacks)
- [SSO Attacks](#sso-attacks)
- [IAM/AWS](#iamaws)
- [Akamai](#akamai)
- [Email/m365 Attacks](#emailm365-attacks)
- [Thin Clients](#thin-clients)
- [Jira/Confluence](#jiraconfluence)
- [License](#license)


# Internal Network
1. **Standard User Data Access Assessment**  
   Investigate what sensitive information a standard user can access, focusing on potential data leaks or unauthorized access to confidential information.  
   - *Tool*: LinEnum  
   - *Description*: Run LinEnum for assessing what data and system functionalities are accessible with standard user privileges.

2. **User Privilege Escalation Techniques**  
   Evaluate common methods for escalating privileges from a standard user to higher levels, using widely known exploits or misconfigurations.  
   - *Tool*: BeRoot  
   - *Description*: Utilize BeRoot on Linux/Windows systems to find common privilege escalation vulnerabilities.

3. **Service Privilege Escalation Techniques**  
   Find out a way to elevate the privilege of a standard service account to root/admin account and identify what else can be exploited post-escalation.

4. **Unauthorized Software Installation Check**  
   Test the ability of a standard user to install unauthorized software, indicating potential weaknesses in software restriction policies.  
   - *Tool*: Custom scripts  
   - *Description*: Write and execute scripts to test if a user can bypass software installation restrictions.

5. **User Role Boundaries Effectiveness**  
   Examine the enforcement and effectiveness of user role boundaries to identify any excessive permissions or role misconfigurations.  
   - *Tool*: BloodHound  
   - *Description*: Employ BloodHound to analyze and visualize user role boundaries and permissions in the network.

6. **Internal Software Vulnerability Scan**  
   Conduct vulnerability scanning on internal software or services to identify potential exploits or weaknesses.  
   - *Tool*: Qualys  
   - *Description*: Conduct vulnerability assessments using OpenVAS on internal applications and services.

7. **Password Management and Storage Security**  
   Assess the security of password management and storage, including attempts to extract stored passwords or keychain data.  
   - *Tool*: John the Ripper  
   - *Description*: Test the strength of stored passwords using John the Ripper.

8. **Network Services Mapping**  
   Perform a network scan to map out services running within the network, focusing on identifying unprotected services or those with known vulnerabilities.  
   - *Tool*: Nmap  
   - *Description*: Utilize Nmap for detailed network mapping and service identification.

9. **Sensitive File Access via Standard User Account**  
   Test access to sensitive files from a standard user account on a shared system, such as a Windows machine, to assess file-sharing security.  
   - *Tools*: Accesschk, Snaffler  
   - *Description*: Use Accesschk to assess what files a standard user can access on Windows systems.

10. **Network Traffic Sniffing for Data Leakage**  
    Use network sniffing tools to identify if sensitive data, such as credentials, can be captured from network traffic.  
    - *Tools*: Wireshark, Responder, Inveigh  
    - *Description*: Employ Wireshark for capturing and analyzing network traffic to detect data leaks.

11. **Internal Reconnaissance and Asset Identification**  
    Conduct internal reconnaissance to identify critical assets and services running within the network.  
    - *Tool*: Nmap  
    - *Description*: Conduct network reconnaissance using Nmap to identify critical assets.

12. **Wireless Network Penetration Test**  
    Evaluate the security of internal wireless networks, focusing on weak encryption, poor authentication methods, and rogue access points.  
    - *Tool*: Aircrack-ng  
    - *Description*: Test wireless network security using Aircrack-ng.

13. **Phishing Simulation Against Employees**  
    Run a controlled phishing campaign to assess employee awareness and susceptibility to social engineering attacks.  
    - *Tool*: Gophish  
    - *Description*: Run phishing simulations with Gophish to assess employee security awareness.

14. **Remote Access Vulnerabilities Assessment**  
    Examine the security of remote access points, including VPNs, for potential vulnerabilities and unauthorized access risks.  
    - *Tool*: Nmap  
    - *Description*: Evaluate remote access points for vulnerabilities using Nmap.

15. **Physical Security Check for Network Access**  
    Test physical security measures to assess the risk of unauthorized individuals gaining network access from within the premises.  
    - *Tools*: Physical inspection and testing  
    - *Description*: Conduct physical security testing to assess network access controls.

16. **Segmentation and Lateral Movement Test**  
    Evaluate network segmentation and controls preventing lateral movement within the network.  
    - *Tool*: BloodHound  
    - *Description*: Analyze network segmentation and test for lateral movement opportunities using BloodHound.

17. **Incident Response Efficacy Test**  
    Simulate an attack to assess the effectiveness of the incident response team and monitoring systems in detecting and responding to breaches.  
    - *Tools*: Simulated attack scenarios  
    - *Description*: Simulate attacks and monitor the incident response team's actions.

18. **Email System Security Assessment**  
    Test email systems for vulnerabilities like spam filtering effectiveness and susceptibility to malware.  
    - *Tool*: MailTester  
    - *Description*: Use MailTester to evaluate the security of email systems, including spam and malware filtering.

19. **User Account Enumeration and Reconnaissance**  
    Attempt to enumerate user accounts and gather information on network users and their privileges.  
    - *Tool*: BloodHound  
    - *Description*: Use BloodHound for in-depth user account enumeration and network reconnaissance.

20. **Endpoint Security Evaluation**  
    Assess the security of end-user devices, focusing on antivirus effectiveness, patch levels, and endpoint protection measures.  
    - *Tool*: Nessus  
    - *Description*: Use Nessus to evaluate endpoint security and identify potential vulnerabilities.

21. **Database Security and Access Controls Test**  
    Evaluate the security of internal databases, focusing on access controls, data encryption, and SQL injection vulnerabilities.  
    - *Tool*: Sqlmap  
    - *Description*: Assess database security, particularly for SQL injection vulnerabilities, using Sqlmap.

22. **Hostname Discovery**  
    Discover internal hostnames and assets on network via LLMNR/NBT-NS Poisoning.  
    - *Tools*: Responder, Inveigh  
    - *Description*: Once on the internal network, listen on all interfaces.

23. **Identifying Application Stack Vulnerabilities across the entire corporate network**  
    Check the high and critical severity vulnerabilities with Nuclei.  
    - *Tool*: Nuclei  
    - *Description*: Run Nuclei to check high and critical severity vulnerabilities in the corp network IP ranges.

24. **Debug Ports Open**  
    Check whether high-numbered developer debug ports are open that also allow RCE.  
    - *Tools*: Nmap, Ncat  
    - *Description*: Service scan with Nmap on all ports; interact with service via Ncat.
   
# Github

1. **Clone GitHub Data**  
   Cloning GitHub data through a Python script.

2. **Sensitive Data Exposure in Repositories**  
   Repositories often contain sensitive data, making this a common attack vector and a realistic threat.  
   - *Tools*: GitRob, Gitleaks  
   - *Description*: Use GitRob to scan GitHub repositories for sensitive data like credentials and keys. Employ Gitleaks to detect misconfigured permissions that might expose sensitive data.

3. **Insecure Integration with Third-party Apps**  
   Evaluate the security of third-party applications integrated with GitHub, focusing on data access and permissions.  
   - *Tool*: GitHub's Security Advisories  
   - *Description*: Review GitHub's security advisories for vulnerabilities in third-party apps.

4. **Code Injection or Malicious Code in Repositories**  
   Check for vulnerabilities that could allow code injection or the presence of malicious code within the repositories.  
   - *Tool*: SonarQube  
   - *Description*: Run SonarQube on repositories to detect vulnerabilities and malicious code.

5. **Access Token and SSH Key Leakage**  
   Scan repositories and commit histories for unintentionally committed sensitive tokens or SSH keys.  
   - *Tool*: TruffleHog  
   - *Description*: Use TruffleHog to search through commit histories for high-entropy strings and potentially exposed secrets.

6. **Bypassing Branch Protection Rules**  
   Attempt to bypass branch protection rules to push unauthorized changes or access protected branches.  
   - *Tool*: GHunt  
   - *Description*: Employ GHunt to analyze GitHub profiles for bypass opportunities in branch protections.

7. **API Endpoint Security and Misconfigurations**  
   Test GitHub API endpoints for misconfigurations, insecure direct object references, or improper access controls.  
   - *Tool*: Postman  
   - *Description*: Utilize Postman to test and observe the security of GitHub API endpoints.

8. **Phishing Attacks Targeting Contributors**  
   Simulate phishing attacks to assess the awareness and response of contributors and team members.  
   - *Tool*: Gophish  
   - *Description*: Set up simulated phishing attacks with Gophish to assess contributor awareness.

9. **Manipulating Issues and Comments for Reconnaissance**  
   Explore potential misuse of the issue tracking system to gather intelligence or inject malicious content.  
   - *Tool*: Custom scripting  
   - *Description*: Use custom scripts to automate issue and comment creation for reconnaissance.

10. **Unauthorized Wiki Page Access or Modification**  
    Probing for vulnerabilities in wiki pages that could lead to unauthorized access or content modification.  
    - *Tool*: OWASP ZAP  
    - *Description*: Run OWASP ZAP to test for vulnerabilities in GitHub wiki pages.

11. **Bypassing Automated Code Scanning Tools**  
    Test the ability to bypass or evade integrated automated code scanning and security tools.  
    - *Tool*: CodeQL  
    - *Description*: Experiment with CodeQL to try and bypass GitHub's automated code scanning.

12. **Repository Cloning and Content Manipulation**  
    Attempt to clone protected repositories or manipulate repository content without appropriate authorization.  
    - *Tool*: GitTools  
    - *Description*: Use GitTools for cloning and analyzing repositories for potential manipulation.

13. **User Account Enumeration and Reconnaissance**  
    Attempt to enumerate user accounts and gather information on team members and contributors.  
    - *Tool*: GHunt  
    - *Description*: Utilize GHunt for enumerating user accounts and gathering intelligence.

14. **Pull Request Hijacking or Injection**  
    Explore vulnerabilities in the pull request process, including unauthorized modifications or injection attacks.  
    - *Tool*: Custom scripting  
    - *Description*: Develop custom scripts to simulate pull request hijacking and test for injection vulnerabilities.

15. **Insider Threat Simulation**  
    Simulate actions of an insider threat to identify potential internal vulnerabilities.  
    - *Tool*: Custom scenario development  
    - *Description*: Design custom scenarios to mimic insider threat behaviors and test network resilience.

16. **GitHub Actions Misuse**  
    Test for misconfigurations or vulnerabilities in GitHub Actions workflows that could be exploited.  
    - *Tool*: Act  
    - *Description*: Run Act to locally test GitHub Actions for misconfigurations and potential misuse.

17. **Host Infrastructure Configuration Flaws**  
    Assess security configurations and potential vulnerabilities of the infrastructure hosting your GitHub environment.  
    - *Tool*: Nessus  
    - *Description*: Utilize Nessus for scanning and identifying configuration flaws in the hosting infrastructure.

18. **Security Policy Compliance Check**  
    Ensure that the use of GitHub aligns with internal security policies and best practices.  
    - *Tool*: Compliance audit tools  
    - *Description*: Conduct compliance audits with appropriate tools to ensure GitHub usage meets organizational policies.

19. **Exposed Sensitive Information in Public Gists**  
    Search public gists for accidentally shared sensitive information.  
    - *Tool*: GistScan  
    - *Description*: Use GistScan to search public gists for sensitive information.

20. **Improperly Secured Backup Repositories**  
    Assess the security of backup repositories, focusing on access controls and data protection.  
    - *Tool*: Burp Suite  
    - *Description*: Employ Burp Suite to test the security and access controls of backup repositories.

21. **CI/CD Sabotage**  
    Check access to CI/CD for the ability to add malicious scripts to repos to gain RCE on host after changes are pushed.

# Active Directory 

1. **User Account Enumeration**  
   Enumerate user accounts to identify potential targets for further attacks.  
   - *Tools*: PowerShell scripts, ADExplorer  
   - *Description*: Utilize PowerShell scripts and ADExplorer for detailed user account enumeration.

2. **Privilege Escalation via GPOs**  
   Exploit misconfigured Group Policy Objects (GPOs) to escalate privileges.  
   - *Tools*: BloodHound, gpresult, adPEAS  
   - *Description*: Use BloodHound to analyze GPOs and gpresult to view applied policies.

3. **Kerberos Ticket Attacks**  
   Exploit Kerberos ticketing for unauthorized access.  
   - *Tools*: Mimikatz, Rubeus  
   - *Description*: Utilize Mimikatz and Rubeus for attacks like Golden and Silver Ticket.

4. **Pass-the-Hash (PtH) Attacks**  
   Use captured hash values to authenticate.  
   - *Tools*: Mimikatz, Metasploit  
   - *Description*: Employ Mimikatz for hash extraction and Metasploit for hash use.

5. **Password Spraying Against Common Accounts**  
   Attempt common passwords on accounts.  
   - *Tools*: Hydra, CrackMapExec  
   - *Description*: Use Hydra and CrackMapExec for password spraying attacks.

6. **NTLM Relay Attacks**  
   Exploit NTLM authentication.  
   - *Tools*: Responder, ntlmrelayx, Shadowspray  
   - *Description*: Use Responder for capturing NTLM hashes and ntlmrelayx for relaying.

7. **Extracting Stored Credentials**  
   Retrieve credentials stored on endpoints.  
   - *Tools*: Mimikatz, LaZagne  
   - *Description*: Apply Mimikatz and LaZagne to extract stored credentials.

8. **Lateral Movement via Remote Services**  
   Access remote services across the network.  
   - *Tools*: PsExec, CrackMapExec  
   - *Description*: Employ PsExec and CrackMapExec for lateral movement.

9. **Domain Trust Mapping and Abuse**  
   Explore and exploit domain trusts.  
   - *Tools*: BloodHound, PowerView  
   - *Description*: Use BloodHound and PowerView for mapping and exploiting domain trusts.

10. **SID-History Injection**  
    Exploit SID-History for access.  
    - *Tools*: PowerShell scripts, Mimikatz  
    - *Description*: Utilize PowerShell and Mimikatz for SID-History injection.

11. **AS-REP Roasting**  
    Target accounts without pre-authentication.  
    - *Tools*: Rubeus, GetNPUsers.py  
    - *Description*: Apply Rubeus and GetNPUsers.py for AS-REP Roasting.

12. **Kerberoasting Service Accounts**  
    Crack service account credentials.  
    - *Tools*: Rubeus, Hashcat  
    - *Description*: Use Rubeus to extract hashes and Hashcat for cracking.

13. **GPP Passwords**  
    Extract passwords from Group Policy Preferences.  
    - *Tools*: gpp-decrypt, Metasploit  
   - *Description*: Use gpp-decrypt and Metasploit for extracting GPP passwords.

14. **DNS Poisoning Inside Active Directory**  
    Redirect users via poisoned DNS.  
    - *Tools*: Responder, dnsmasq, dnsgoblin  
    - *Description*: Employ Responder and dnsmasq for DNS poisoning.

15. **Analyzing AD for Old Accounts and Configurations**  
    Identify weak configurations.  
    - *Tools*: OldCmp, PingCastle  
   - *Description*: Use OldCmp and PingCastle for identifying vulnerabilities in Active Directory.

16. **Delegated Permissions Abuse**  
    Exploit excessive delegated permissions.  
   - *Tools*: PowerView, ADExplorer  
   - *Description*: Utilize PowerView and ADExplorer to identify and exploit delegated permissions.

17. **Resource-Based Constrained Delegation Attack**  
    Configure constrained delegation on the resource instead of the service account, allowing unauthorized access.  
   - *Tool*: [Resource-Based Constrained Delegation Attack](https://gist.github.com/tothi/bf6c59d6de5d0c9710f23dae5750c4b9)

18. **Attacking AD-Integrated DNS**  
    Target DNS vulnerabilities.  
   - *Tools*: DNSCmd, PowerShell scripts  
   - *Description*: Apply DNSCmd and custom PowerShell scripts for DNS attacks.

19. **Extracting Clear Text Passwords from Memory**  
    Retrieve passwords from system memory.  
   - *Tools*: Mimikatz, ProcDump  
   - *Description*: Use Mimikatz and ProcDump for memory analysis.

20. **Null Session RID Cycle Attack**  
   Use null sessions to enumerate users with RID cycling.  
   - *Tool*: ridenum  
   - *Description*: Cycle through RIDs to enumerate users with null sessions.

21. **LDAP Signing Not Enforced**  
   Exploit unprotected LDAP communication for privilege escalation.  
   - *Tool*: DavRelayUp  
   - *Description*: Utilize DavRelayUp for exploiting LDAP signing vulnerabilities.

22. **SPN Scanning and Service Account Enumeration**  
   Enumerate service accounts using SPN scanning.  
   - *Tools*: setspn, PowerView  
   - *Description*: Employ setspn and PowerView for service account enumeration.

23. **Attacking Third-Party Applications**  
   Exploit vulnerabilities in integrated third-party applications.  
   - *Tools*: Custom scripts, Vulnerability scanners  
   - *Description*: Use custom scripts and vulnerability scanners to identify vulnerabilities in third-party applications.

24. **ADCS Abuse**  
   Abusing misconfigured templates for privilege escalation or NTLM relaying to obtain certificates.  
   - *Tools*: Certify, Certipy, SharpSpoolTrigger, Rubeus  
   - *Description*: Use Certify and Certipy for detecting or exploiting vulnerable templates; SharpSpoolTrigger for coercing Domain Controller authentication.

25. **Local Privilege Escalation via LAPS**  
   Exploit Local Administrator Password Solution (LAPS) misconfigurations for privilege escalation.  
   - *Tools*: LAPSToolkit, LAPSDumper, dnSpy  
   - *Description*: Enumerate on host machines with LAPSToolkit; dump LAPS passwords with LAPSDumper; disassemble .NET binaries with dnSpy.

26. **Privilege Escalation via DCSync**  
   Leverage Directory Replication Service Remote Protocol for privilege escalation.  
   - *Tools*: secretsdump, Mimikatz  
   - *Description*: Use secretsdump for remote DCSync; employ Mimikatz for local DCSync.

27. **Host Persistence**  
   Gain persistence via scheduled tasks, startup folders, registry keys, and certificates.  
   - *Tools*: SharPersist, Certify, Rubeus, Mimikatz  
   - *Description*: Use these tools for persistence through specific techniques like scheduled tasks and registry keys.

28. **Elevated Persistence**  
   Gain elevated persistence via WMI event subscription, Golden Ticket, or Diamond Ticket.  
   - *Tools*: PowerLurk.ps1, Rubeus, Mimikatz, Certify  
   - *Description*: Use these tools in elevated sessions for persistence through advanced methods like WMI event subscriptions.

# Azure/Entra Active Directory

1. **Tenant Domains Enumeration**  
   Enumerate the domains of an Azure tenant, revealing all associated domains.  
   - *Tools*: AADInternals, manual URL calls  
   - *Description*: Run the tool after obtaining tenant information.

2. **User and Group Enumeration**  
   Enumerate user and group information available within the Azure tenant.

3. **Brute Force Attack on User Accounts**  
   Attempt to access user accounts through brute force attacks to guess weak passwords.  
   - *Tool*: AzureAD_Autologon_Brute (GitHub: nyxgeek/AzureAD_Autologon_Brute)  
   - *Description*: This tests for vulnerabilities in password policies and account lockout settings.

4. **Phishing Attack to Gain Credentials**  
   Craft phishing campaigns targeting Azure Active Directory (AAD) users to steal their credentials.  
   - *Tool*: Zphisher (GitHub: htr-tech/zphisher)  
   - *Description*: This tests the effectiveness of user training and email filtering systems.

5. **Token Hijacking**  
   Intercept and exploit authentication tokens to gain unauthorized access.  
   - *Tools*: jwtXploiter, jwt_tool  
   - *Description*: This can test the robustness of token handling and session security.

6. **Exploiting Misconfigured Permissions**  
   Identify and exploit misconfigured user or admin roles in AAD to escalate privileges or access restricted data.  
   - *Tools*: o365creeper, CloudBrute, cloud_enum, Azucar, ScoutSuite, BlobHunter, Office 365 User Enumeration, CloudFox, Monkey365 (GitHub: Kyuu-Ji/Awesome-Azure-Pentest)  
   - *Description*: Test for permission misconfigurations that could lead to privilege escalation.

7. **Directory Traversal/Enumeration**  
   Attempt to enumerate directory information or perform traversal attacks to access unauthorized information or directories in AAD.

8. **SQL Injection in AAD Integrated Applications**  
   Test for SQL injection vulnerabilities in applications that integrate with AAD for authentication.  
   - *Description*: SQL injection can lead to unauthorized data access.

9. **Cross-Site Scripting (XSS) in AAD Integrated Apps**  
   Identify XSS vulnerabilities in web applications using AAD for authentication.  
   - *Description*: XSS can compromise user data and sessions.

10. **Man-in-the-Middle (MitM) Attacks on AAD Communications**  
    Intercept communications between users and AAD services to capture sensitive data or manipulate transactions.  
    - *Tools*: mitmproxy, MITMf, proxy.py  
    - *Description*: Test for potential MitM vulnerabilities in AAD communications.

11. **API Security Testing**  
    Assess the security of AAD APIs, looking for vulnerabilities like improper authentication, lack of rate limiting, or insecure data exposure.  
    - *Description*: Testing focuses on finding insecure endpoints or weak security measures.

12. **Testing Custom Conditional Access Policies**  
    Evaluate the effectiveness and potential bypasses of custom conditional access policies set up in AAD.  
    - *Description*: Test for weak spots in custom conditional access policies.

# VPN
1. **Recon all IP subnet for VPN**  
   Scan and enumerate all IPs within a VPN subnet to understand the network layout and discover hosts.  
   - *Tools*: Nmap, Angry IP Scanner  
   - *Description*: Nmap is a powerful network scanning tool that can detect hosts and services. Angry IP Scanner is a simpler IP scanner that can quickly identify active devices on a subnet.

2. **Check for open source vulnerability assessment methodologies**  
   Explore methodologies used in open-source projects to assess vulnerabilities.  
   - *Tools*: OWASP, NIST, CIS Controls  
   - *Description*: OWASP provides comprehensive guides on vulnerability assessments. NIST and CIS Controls offer frameworks and guidelines for assessing and managing vulnerabilities.

3. **Split tunneling**  
   Occurs when a user accesses an insecure Internet connection while using a VPN.  
   - *Tools*: VPN configuration tools, network monitoring software  
   - *Description*: Tools like Wireshark can help monitor network traffic for split tunneling. VPN configuration tools can identify split tunneling risks and ensure secure VPN connections.

4. **Highly privileged accounts**  
   Occurs when admins grant users excessive network access rights.  
   - *Tools*: BloodHound, PowerView  
   - *Description*: BloodHound visualizes Active Directory relationships, allowing you to identify privileged accounts. PowerView can be used to enumerate permissions and detect overly privileged accounts.

5. **DNS leaks**  
   Occur when a computer uses a default DNS connection instead of the VPN’s secure DNS server.  
   - *Tools*: DNSLeakTest, dnsmasq  
   - *Description*: DNSLeakTest helps identify DNS leaks. dnsmasq is a DNS forwarder that can mitigate DNS leak risks.

6. **Finding out the type of authentication used by a VPN**  
   Determine the authentication mechanism used by a VPN.  
   - *Tools*: Wireshark, OpenVPN  
   - *Description*: Wireshark can capture VPN traffic to understand the authentication process. OpenVPN logs can reveal the type of authentication used.

7. **Exploiting the weaknesses in PSK (pre-shared key) authentication mechanism**  
   Test for vulnerabilities in pre-shared key (PSK) authentication in VPNs.  
   - *Tools*: Aircrack-ng, Hashcat  
   - *Description*: Aircrack-ng is used for cracking PSK-based VPNs, and Hashcat is a popular tool for brute-forcing PSK keys.

# Printer Services

1. **Sniffing and Intercepting Print Jobs**  
   Intercept and analyze print jobs to extract sensitive information.  
   - *Tools*: Wireshark  
   - *Description*: Wireshark captures and analyzes network traffic, allowing you to inspect and extract data from print jobs.

2. **Unauthorized Access via Printer Protocols**  
   Gain unauthorized access or control of a printer using printer-specific protocols like IPP or PJL.  
   - *Tools*: PRET (Printer Exploitation Toolkit)  
   - *Description*: PRET can interact with printers using various protocols to gain unauthorized access or control.

3. **Default Credentials and Misconfigurations**  
   Identify and exploit printers with default credentials or misconfigurations.  
   - *Tools*: Hydra, Nmap  
   - *Description*: Hydra can brute-force common printer credentials. Nmap can help identify printers with open ports and misconfigurations.

4. **Compromising Network Printers to Sniff on Host Machine Traffic**  
   Compromise network printers to intercept and analyze network traffic from specific Windows machines in the corporate network.  
   - *Tools*: Wireshark, TCP Shark  
   - *Description*: Wireshark can monitor and capture network traffic, while TCP Shark specializes in TCP-based traffic analysis.

5. **Printer-based DDoS Attacks**  
   Commandeer network printers to launch Distributed Denial of Service (DDoS) attacks.  
   - *Tools*: LOIC, HP JetDirect Exploitation  
   - *Description*: LOIC can be used to launch DDoS attacks, while vulnerabilities in HP JetDirect can allow printers to be exploited for DDoS.

6. **Abusing Printer Storage**  
   Exploit printer hard drives or memory to store malicious payloads or exfiltrate data.  
   - *Tools*: PRET, Metasploit  
   - *Description*: PRET can access printer storage, while Metasploit can deploy malicious payloads to printer memory.

7. **Externally Accessible Printers**  
   Identify if the printer can print jobs for users not connected via VPN or in the office.  
   - *Method*: Manual testing with mobile phones or external laptops  
   - *Description*: This involves testing printer access from outside the corporate network to determine if the printer is publicly accessible.

# Containers

1. **Unpatched Vulnerabilities in Container Images**  
   Discover and exploit vulnerabilities in container images that could lead to code execution or data leakage.  
   - *Tools*: Clair, Trivy  
   - *Description*: Clair is a vulnerability scanner for containers, detecting vulnerabilities in Docker and OCI images. Trivy is a comprehensive security scanner for containers, checking for vulnerabilities in images, repositories, and other resources.

2. **Exploiting Insecure Container Orchestration**  
   Identify weaknesses in Kubernetes orchestration, such as insecure API endpoints or misconfigured role-based access controls (RBAC).  
   - *Tools*: kube-hunter, RBAC Lookup  
   - *Description*: kube-hunter scans Kubernetes clusters for security issues, while RBAC Lookup checks role-based access controls to identify misconfigurations.

3. **Host Kernel Exploitation via Containers**  
   Exploit vulnerabilities in the container runtime or kernel to escape the container and compromise the host system.  
   - *Tools*: Exploit scripts, container runtime monitoring tools  
   - *Description*: Host kernel vulnerabilities can be exploited to escape containers. These tools monitor container runtimes for suspicious activity or known exploits.

4. **Compromised Secrets Management**  
   Test the security of secrets management in containerized environments.  
   - *Tools*: kubeaudit, HashiCorp Vault  
   - *Description*: kubeaudit checks for insecure secrets management in Kubernetes. HashiCorp Vault is used to secure, store, and manage secrets in containers.

5. **Side-channel Attacks in Multi-tenant Environments**  
   Execute side-channel attacks in a Kubernetes cluster shared by multiple tenants to extract information from neighboring containers.  
   - *Tools*: Cache timing analysis, inter-process communication monitoring tools  
   - *Description*: Side-channel attacks use indirect methods to extract sensitive information from shared environments. Cache timing analysis tools can detect these attacks.

6. **Network Segmentation and Firewall Rules for Containers**  
   Test the effectiveness of network policies and firewall rules in isolating containers and pods.  
   - *Tools*: Nmap, Calico  
   - *Description*: Nmap can be used to test network segmentation and detect open ports in containers. Calico is a popular Kubernetes network policy engine for configuring firewall rules and segmenting networks.

7. **Abusing Kubernetes Autoscaling Mechanisms**  
   Trigger Kubernetes autoscaling to create resource exhaustion or deploy pods with weaker security configurations.  
   - *Tools*: Kubernetes API, custom scripts  
   - *Description*: These tools can interact with the Kubernetes API to trigger autoscaling events, potentially causing resource exhaustion or exploiting autoscaling misconfigurations.

8. **Intercepting Inter-Container Communication**  
   Eavesdrop or modify traffic between containers within the same Kubernetes pod or Docker network.  
   - *Tools*: Wireshark, TCP Shark  
   - *Description*: Wireshark captures and analyzes network traffic between containers, while TCP Shark is used to inspect TCP-based communication within container networks.

9. **Insecure Container Configurations**  
   Identify and exploit misconfigurations in Docker containers or Kubernetes pods that could lead to unauthorized access or privilege escalation.  
   - *Tools*: Docker Bench for Security, kube-bench  
   - *Description*: Docker Bench for Security checks for insecure Docker configurations, while kube-bench assesses Kubernetes pods for misconfigurations.

10. **Docker Registry Dump**  
    Scan a Docker subnet for a container holding the Docker registry, then dump Docker images and search for credentials and keys.  
    - *Tools*: DockerRegistryGrabber  
    - *Description*: This tool retrieves Docker images from a Docker registry, allowing further analysis for sensitive information like credentials or keys.

# EDR Bypass

1. **Blue Team Detection Rules**  
   Detection rules created by the Blue Team to identify and respond to security threats.  
   - *Tools*: SIEM systems (like Splunk, ELK Stack), EDR solutions  
   - *Description*: SIEM systems and EDR solutions use predefined rules to detect security incidents and alert the Blue Team.

2. **Certificate Spoofing Attack**  
   Spoof an online certificate to bypass antivirus (AV) detection.  
   - *Tools*: CarbonCopy  
   - *Description*: CarbonCopy can spoof SSL/TLS certificates to test for vulnerabilities and bypass AV security.

3. **Windows Defender Exceptions**  
   Modify Windows Defender to create exceptions for specific folders, allowing malware to evade detection.  
   - *Tools*: PowerShell scripts, Windows Defender settings  
   - *Description*: Custom PowerShell scripts can modify Windows Defender settings to create exceptions for specific folders, allowing malware to hide from Defender.

4. **Malware in Exception Folders**  
   Place simple malware in an exception folder to test if Defender can detect or remove it.  
   - *Tools*: Custom scripts, malware samples  
   - *Description*: This involves creating custom scripts or using malware samples to test Defender's detection capabilities in exception folders.

5. **Bypass Defender using Standard Frameworks**  
   Use frameworks to bypass Windows Defender.  
   - *Tools*: Veil  
   - *Description*: Veil is a framework that generates AV-evasive payloads to test Defender's security mechanisms.

6. **Collaboration with Detection Team**  
   Collaborate with the detection team to share findings and results.  
   - *Tools*: Manual collaborations, meetings, documentation  
   - *Description*: This involves direct collaboration with the Blue Team to share findings and improve detection rules.

7. **AMSI Bypass**  
   Bypass the Antimalware Scan Interface (AMSI) in Windows systems.  
   - *Tools*: AMS-BP  
   - *Description*: AMS-BP offers various methods to bypass AMSI, allowing code execution without triggering security scans.

8. **LOLBAS: Bypass Defender via Living off the Land Binaries, Scripts, and Libraries**  
   Use native Windows binaries and scripts to bypass Defender.  
   - *Tools*: msbuild, PowerShell, certutil  
   - *Description*: These tools are native to Windows and can be used to perform malicious actions without raising suspicion, thus bypassing Defender.

9. **Process and DLL Injection**  
   Inject custom shell code into processes or DLLs to evade Endpoint Detection and Response (EDR).  
   - *Tools*: Visual Studio  
   - *Description*: Visual Studio can compile custom code for process or DLL injection, allowing attackers to evade EDR detection.

10. **Direct Syscalls**  
    Use direct system calls to avoid EDR hooks in NTDLL.  
    - *Tools*: SysWhispers3  
    - *Description*: SysWhispers3 creates headers, source, and assembly instruction files for direct system calls, allowing code execution while avoiding EDR hooks in NTDLL.

# Wireless Attacks

1. **WEP Cracking**  
   Exploiting the weaknesses in WEP encryption to gain unauthorized access.  
   - *Tools*: Aircrack-ng  
   - *Description*: Captures packets to exploit the Initialization Vector (IV) weakness and crack WEP encryption.

2. **WPA/WPA2 PSK Cracking**  
   Using a brute force approach with dictionaries to crack the pre-shared key.  
   - *Tools*: coWPAtty, Aircrack-ng  
   - *Description*: Performs a dictionary attack against WPA-PSK/WPA2-PSK using a wordlist or brute force techniques.

3. **WPA2 Enterprise Downgrade Attack**  
   Forcing a client to connect to a less secure authentication method.  
   - *Tools*: Hostapd  
   - *Description*: Hostapd creates a rogue Access Point (AP) to perform the downgrade attack, coercing clients into connecting with weaker security.

4. **Evil Twin Attack**  
   Creating a deceptive duplicate of a legitimate access point.  
   - *Tools*: Airgeddon  
   - *Description*: Airgeddon sets up a rogue AP with the same SSID as a legitimate AP to capture credentials.

5. **Wireless Deauthentication Attack**  
   Forcing clients to disconnect and reconnect to capture handshakes.  
   - *Tools*: Aireplay-ng  
   - *Description*: Sends deauth packets to disconnect clients from the network, facilitating the capture of WPA handshakes for cracking.

6. **Karma Attack**  
   Impersonating all SSIDs requested by clients to lure them to a rogue AP.  
   - *Tools*: Bettercap  
   - *Description*: Bettercap's Karma attack feature impersonates multiple SSIDs to attract clients to a rogue AP.

7. **PMKID Harvesting**  
   Capturing the PMKID from the AP for offline cracking.  
   - *Tools*: Hcxdumptool, Hcxtools  
   - *Description*: These tools capture the Pairwise Master Key Identifier (PMKID) from the AP, allowing for offline cracking.

8. **Rogue AP with Captive Portal**  
   Setting up a fake AP with a portal to phish for credentials.  
   - *Tools*: WiFiphisher  
   - *Description*: Creates a rogue AP with a phishing portal to capture credentials or manipulate user interactions.

9. **Pixie Dust Attack on WPS**  
   Exploiting WPS protocol vulnerabilities.  
   - *Tools*: Reaver, Pixiewps  
   - *Description*: Reaver and Pixiewps exploit weaknesses in the WPS protocol to retrieve the WPA/WPA2 passphrase.

10. **Bluetooth Snarfing**  
    Accessing unauthorized information over Bluetooth connections.  
   - *Tools*: Bluesnarfer  
   - *Description*: Exploits Bluetooth vulnerabilities to extract data or control Bluetooth-enabled devices.

11. **KRACK Attack Against WPA2**  
    Targeting the four-way handshake of WPA2.  
   - *Tools*: KRACK Scripts, Hostapd-wpe  
   - *Description*: These tools demonstrate and exploit the KRACK vulnerability, allowing attackers to manipulate WPA2 handshakes.

12. **RF Jamming**  
    Intentionally disrupting wireless communications.  
   - *Tools*: HackRF One  
   - *Description*: HackRF One can transmit signals that interfere with wireless network communications, disrupting service.

13. **MITM on Encrypted Wi-Fi**  
    Intercepting and manipulating traffic in encrypted networks.  
   - *Tools*: Bettercap  
   - *Description*: Bettercap allows for man-in-the-middle attacks on encrypted Wi-Fi, potentially compromising data integrity and confidentiality.

14. **SSID Cloaking and Discovery**  
    Revealing networks that hide their SSID.  
   - *Tools*: Airodump-ng  
   - *Description*: Discovers and reveals hidden network SSIDs by passively sniffing wireless traffic.

15. **GPS Spoofing in Wireless Networks**  
    Manipulating GPS signal reception.  
   - *Tools*: GPS-SDR-SIM, HackRF One  
   - *Description*: These tools generate and transmit fake GPS signals to manipulate wireless networks that rely on GPS-based location information.

16. **Wireless Network Mapping**  
    Charting out Wi-Fi networks and identifying potential targets.  
   - *Tools*: Kismet, WiGLE  
   - *Description*: Kismet and WiGLE map wireless networks and provide insights into potential targets.

17. **Credential Harvesting via Probe Requests**  
    Collecting probe requests for intelligence.  
   - *Tools*: Wireshark  
   - *Description*: Captures and analyzes probe requests from devices, potentially revealing information that could be used for credential harvesting.

18. **Client Isolation Attacks**  
   Breaching network measures that prevent client-to-client communication.  
   - *Tools*: Aireplay-ng, Besside-ng  
   - *Description*: Forces client reconnections and attacks network isolation mechanisms to establish client-to-client communication.

19. **Passive Eavesdropping**  
   Listening to wireless traffic to gather data.  
   - *Tools*: Airodump-ng  
   - *Description*: Passively sniffs wireless traffic to gather information without actively transmitting data.

20. **XSS via Wi-Fi Hotspots**  
   Injecting scripts into webpages accessed over hotspots.  
   - *Tools*: BeEF, OWASP ZAP, Burp Suite  
   - *Description*: BeEF manages XSS payloads, while OWASP ZAP and Burp Suite can modify web traffic to inject scripts into Wi-Fi hotspot sessions.

# Database attacks

1. **SQL Injection**  
   Exploiting poorly sanitized input fields to execute unauthorized SQL commands.  
   - *Tools*: Sqlmap  
   - *Description*: Sqlmap automates the detection and exploitation of SQL injection vulnerabilities.

2. **Privilege Escalation via xp_cmdshell**  
   Abusing the xp_cmdshell stored procedure to execute arbitrary commands.  
   - *Tools*: Metasploit  
   - *Description*: Metasploit contains modules that can exploit xp_cmdshell, allowing privilege escalation in SQL Server environments.

3. **Database Link Crawling**  
   Using linked servers to pivot to other databases within the network.  
   - *Tools*: PowerShell Scripts  
   - *Description*: PowerShell scripts can be used to explore and navigate through linked servers within SQL Server environments.

4. **Backup Files Access**  
   Locating and accessing database backup files.  
   - *Tools*: PowerShell Scripts  
   - *Description*: PowerShell scripts can search for and extract backup files in a Windows environment.

5. **MSSQL Default Passwords**  
   Guess default passwords for all MSSQL server instances found in the corporate network range.  
   - *Tools*: Hydra  
   - *Description*: Hydra is a password-cracking tool that can perform brute-force attacks to find default or weak passwords.

6. **MSSQL Password Hash Extraction**  
   Extracting password hashes from the master database for offline cracking.  
   - *Tools*: sqsh  
   - *Description*: sqsh is an MSSQL CLI tool that can execute SQL commands to extract password hashes from the database.

7. **MSSQL Database Extraction**  
   Extract a database from a compromised MSSQL instance.  
   - *Tools*: Microsoft SQL Server Studio  
   - *Description*: SQL Server Studio can extract databases for further analysis or exploitation.

8. **Buffer Overflow Exploit**  
   Targeting buffer overflow vulnerabilities in MySQL versions.  
   - *Tools*: Metasploit  
   - *Description*: Metasploit includes modules designed to exploit buffer overflows in MySQL databases.

9. **UDF Injection**  
   Injecting malicious User-Defined Functions to gain shell access in MySQL.  
   - *Tools*: UDF Repository  
   - *Description*: A collection of pre-compiled UDFs for MySQL exploitation, allowing arbitrary code execution within the database.

10. **Database Enumeration**  
    Gathering detailed information about the database schema.  
   - *Tools*: Nmap  
   - *Description*: Nmap uses its scripting engine to enumerate MySQL databases and gather schema information.

11. **MySQL Tuning Exploitation**  
    Taking advantage of misconfigurations detected by MySQL tuning scripts.  
   - *Tools*: MySQLTuner  
   - *Description*: MySQLTuner analyzes MySQL performance and highlights misconfigurations that can be exploited.

12. **SQL Injection in PostgreSQL**  
    Performing SQL injection specific to PostgreSQL's syntax and features.  
   - *Tools*: BBQSQL  
   - *Description*: BBQSQL is a blind SQL injection exploitation tool that can adapt to PostgreSQL.

13. **Unsecured pgAdmin Interface**  
    Accessing a database via a misconfigured pgAdmin web interface.  
   - *Tools*: Selenium  
   - *Description*: Selenium is used to automate the exploitation of pgAdmin interfaces accessible without proper security measures.

14. **PostgreSQL File and Code Execution**  
    Exploiting the COPY FROM PROGRAM feature to execute arbitrary code.  
   - *Tools*: Custom Exploits  
   - *Description*: These are tailored exploits that leverage PostgreSQL vulnerabilities to execute code.

15. **Postgres Pass-the-Hash**  
    Utilizing captured password hashes to authenticate without a password in PostgreSQL.  
   - *Tools*: Metasploit  
   - *Description*: Metasploit contains modules to pass-the-hash with PostgreSQL databases.

16. **Extension Exploitation in PostgreSQL**  
    Abusing PostgreSQL extensions to run arbitrary code or escalate privileges.  
   - *Tools*: Metasploit, Custom Scripts  
   - *Description*: Scripts or modules that exploit vulnerable PostgreSQL extensions for code execution or privilege escalation.

17. **NoSQL Injection**  
    Injecting malicious code into NoSQL databases like MongoDB.  
   - *Tools*: NoSQLMap  
   - *Description*: NoSQLMap automates NoSQL injection testing and exploitation in databases like MongoDB.

18. **Insecure Direct Object References**  
   Accessing unsecured data references in NoSQL databases.  
   - *Tools*: Burp Suite  
   - *Description*: Burp Suite can test for insecure direct object references and unauthorized data exposure in NoSQL databases.

19. **Default Configuration Exploitation in NoSQL**  
   Taking advantage of default NoSQL configurations for unauthorized access.  
   - *Tools*: MongoDB Scanner  
   - *Description*: This tool scans for MongoDB databases with default configurations, indicating potential security risks.

20. **NoSQL Ransomware**  
   Encrypting NoSQL databases to demand a ransom.  
   - *Tools*: Custom Ransomware Scripts  
   - *Description*: Tailored scripts to encrypt NoSQL databases for ransomware simulation.

21. **TNS Listener Password Guessing**  
   Guessing the password for the Oracle TNS listener service.  
   - *Tools*: Hydra  
   - *Description*: Hydra can guess passwords for the TNS listener service, potentially compromising Oracle databases.

22. **TNS Listener Poisoning**  
   Exploiting the Oracle TNS listener service to hijack sessions.  
   - *Tools*: Metasploit  
   - *Description*: Metasploit contains modules to perform TNS poisoning attacks in Oracle databases.

23. **Redis Replication Abuse**  
   Exploit misconfigurations to sync with the target Redis server to dump or modify session keys.  
   - *Tools*: redis, redis-cli  
   - *Description*: These tools can sync with the target Redis server and execute commands for dumping or modifying session keys.

# SSO Attacks

1. **Credential Stuffing Attack**  
   Automate login attempts using breached or commonly used credentials to bypass authentication controls.  
   - *Tools*: Custom scripts, Hydra  
   - *Description*: Tools that can automate login attempts with large sets of credentials to test for weak authentication controls.

2. **Phishing Campaign**  
   Conduct a phishing campaign to deceive users into entering their SSO credentials on a fake login page.  
   - *Tools*: Gophish, Zphisher  
   - *Description*: These tools create fake phishing pages to capture Single Sign-On (SSO) credentials from unsuspecting users.

3. **Session Hijacking**  
   Intercept and steal session tokens during transit to gain unauthorized access to a user session.  
   - *Tools*: Wireshark, Bettercap  
   - *Description*: These tools can capture and analyze session tokens in transit, allowing attackers to hijack user sessions.

4. **Man-in-the-Middle (MitM) Attack**  
   Position between the user and the SSO server to capture or manipulate data during a transaction.  
   - *Tools*: mitmproxy, Burp Suite  
   - *Description*: Tools that can intercept and manipulate network traffic between users and SSO servers to capture sensitive information.

5. **Cross-Site Scripting (XSS)**  
   Inject malicious scripts into the SSO login page or redirect pages to steal session cookies or redirect users to malicious sites.  
   - *Tools*: OWASP ZAP, BeEF  
   - *Description*: These tools can inject or manipulate scripts to conduct XSS attacks on SSO-related websites.

6. **Cross-Site Request Forgery (CSRF)**  
   Trick users into performing actions on the SSO service without their knowledge.  
   - *Tools*: Burp Suite, OWASP ZAP  
   - *Description*: Tools for testing CSRF vulnerabilities, allowing attackers to force users into performing unintended actions.

7. **SQL Injection**  
   Manipulate backend databases by injecting malicious SQL through input fields in the SSO system.  
   - *Tools*: Sqlmap, SQL Injection scripts  
   - *Description*: Tools and scripts that can automate SQL injection attacks to manipulate database operations.

8. **Token Manipulation**  
   Modify or forge authentication tokens to escalate privileges or impersonate legitimate users.  
   - *Tools*: jwt_tool, Burp Suite  
   - *Description*: Tools to analyze and manipulate JSON Web Tokens (JWTs) or other authentication tokens for malicious purposes.

9. **Pass-the-Hash**  
   Utilize hash interception techniques to authenticate using stolen hash values instead of plaintext passwords.  
   - *Tools*: Metasploit, Mimikatz  
   - *Description*: Tools that allow attackers to authenticate with hash values without needing plaintext passwords.

10. **Password Reset Flaw Exploitation**  
    Exploit weaknesses in the password reset or recovery processes to gain unauthorized access.  
   - *Tools*: Custom scripts, manual testing  
   - *Description*: This involves manipulating password reset processes to gain unauthorized access to accounts.

11. **API Security Flaws**  
    Exploit insecure APIs that the SSO system interacts with to extract sensitive data or perform unauthorized actions.  
   - *Tools*: Postman, OWASP ZAP  
   - *Description*: Tools for testing and exploiting API vulnerabilities to extract sensitive data or perform unauthorized actions.

12. **Denial of Service (DoS)**  
    Overwhelm the SSO service with high volumes of traffic to render it unavailable.  
   - *Tools*: LOIC, custom scripts  
   - *Description*: These tools can generate high volumes of traffic to test for Denial of Service vulnerabilities.

13. **DNS Hijacking**  
    Redirect DNS responses to malicious sites to capture or redirect SSO authentication traffic.  
   - *Tools*: DNSmasq, Bettercap  
   - *Description*: Tools to manipulate DNS responses to redirect users to malicious sites, allowing attackers to capture SSO credentials.

14. **Encryption Flaws Exploitation**  
    Exploit weak encryption algorithms or poor key management practices in the SSO system.  
   - *Tools*: Custom scripts, manual testing  
   - *Description*: This involves testing for weak encryption methods or poor key management in the SSO system.

15. **Directory Traversal**  
   Exploit insufficient security validation to access files or directories outside the intended path.  
   - *Tools*: Burp Suite, OWASP ZAP  
   - *Description*: These tools can be used to test for directory traversal vulnerabilities and gain unauthorized access to files.

16. **Subdomain Takeover**  
   Exploit misconfigured DNS entries for subdomains used by the SSO system to redirect users to malicious sites.  
   - *Tools*: Custom scripts, DNS testing tools  
   - *Description*: Tools that test for misconfigured DNS subdomains, leading to potential subdomain takeovers.

17. **Backdoor Accounts**  
   Create or exploit backdoor accounts in the SSO system to maintain persistent access.  
   - *Tools*: Metasploit, custom scripts  
   - *Description*: These tools allow attackers to create or exploit backdoor accounts for persistent access to SSO systems.

18. **Malware Injection**  
   Compromise the SSO system or related infrastructure with malware to establish command and control.  
   - *Tools*: Metasploit, custom scripts  
   - *Description*: These tools can inject malware into SSO systems, allowing command and control by attackers.

19. **Identity Federation Exploits**  
   Exploit flaws in identity federation implementations to escalate access across linked systems.  
   - *Tools*: Custom scripts, manual testing  
   - *Description*: These tools can manipulate identity federation to gain unauthorized access across multiple linked systems.

20. **OAuth Vulnerabilities**  
   Exploit vulnerabilities in the OAuth implementation, such as stealing authorization codes or tokens.  
   - *Tools*: Burp Suite, Postman  
   - *Description*: Tools that test for OAuth vulnerabilities, enabling unauthorized access or privilege escalation.

21. **Two-Factor Authentication Bypass**  
   Identify and exploit weaknesses in the two-factor authentication process, such as intercepting SMS codes.  
   - *Tools*: SimSwap, manual testing  
   - *Description*: SimSwap and other methods are used to bypass two-factor authentication by intercepting SMS codes.

22. **Supply Chain Attack**  
   Compromise third-party libraries or software used by the SSO system to inject malicious code.  
   - *Tools*: Dependency-checking tools, SCA software  
   - *Description*: These tools can identify and exploit vulnerabilities in third-party libraries or software used by SSO systems.

23. **Memory Scraping on Authentication Servers**  
   Extract sensitive data directly from the memory of systems handling authentication.  
   - *Tools*: Mimikatz, Volatility  
   - *Description*: These tools can extract sensitive data from memory, including authentication tokens and session information.

24. **Server-Side Request Forgery (SSRF)**  
   Exploit the SSO server to make unintended requests to internal services that are otherwise not directly accessible.  
   - *Tools*: Burp Suite, custom scripts  
   - *Description*: These tools allow attackers to test for and exploit SSRF vulnerabilities, which can lead to unauthorized access to internal services.

# IAM/AWS

1. **Recon Tools for Cloud Services**  
   Use reconnaissance tools to identify vulnerabilities and gather information on AWS cloud services.  
   - *Tools*: awspx, cloudsplaining, awsenum, Prowler, enumerate-iam, ScoutSuite  
   - *Description*: These tools scan AWS environments to identify misconfigurations, enumerate IAM permissions, and discover potential attack vectors.

2. **Loose S3 Bucket Permissions**  
   Enumerate permissions and functionality of S3 buckets to determine if ordinary users can access sensitive files.  
   - *Tools*: aws-cli  
   - *Description*: Use the AWS Command Line Interface (CLI) to list and analyze S3 bucket permissions to detect overly permissive access controls.

3. **Unrolled Secrets**  
   Enumerate GitHub repositories for AWS keys that haven't been rotated and determine if you can access sensitive files.  
   - *Tools*: aws-cli, GitHub Search  
   - *Description*: AWS CLI can validate the authenticity of AWS keys found in public repositories, allowing you to check for unrotated secrets.

4. **Metadata from 169.254.169.254**  
   Determine if it is possible to make HTTP requests from an EC2 to query API keys or credentials from this specific endpoint.  
   - *Tools*: aws-cli, curl  
   - *Description*: This endpoint provides instance metadata; attackers can use HTTP requests to access sensitive information or credentials.

5. **Internal Reconnaissance**  
   Resolve policy information from limited IAM user account permissions to identify potential attack paths.  
   - *Tools*: aws-cli  
   - *Description*: This involves determining what actions and resources a given IAM user has access to by examining their policy information.

6. **Vulnerable Existing Lambda Functions**  
   Given an IAM role, determine if any existing Lambda functions can be exploited to escalate privileges.  
   - *Tools*: aws-cli, Lambda function analysis tools  
   - *Description*: These tools analyze Lambda functions for misconfigurations or vulnerabilities that could be exploited for privilege escalation.

7. **Lambda Privilege Escalation (Privesc)**  
   Given an IAM role, determine if it is possible to create a Lambda function to gain admin privileges.  
   - *Tools*: aws-cli  
   - *Description*: Create a Lambda function with a high-privilege role to elevate an IAM user's permissions, potentially granting admin-level access.

8. **Vulnerable Cognito**  
   Find entry points to gain a Cognito userpool client ID, enumerate restrictions, and exploit misconfigurations in Amazon Cognito to elevate your privileges.  
   - *Tools*: aws-cli, custom scripts  
   - *Description*: This involves exploiting misconfigurations in Amazon Cognito, allowing attackers to bypass restrictions or gain elevated access.

9. **IAM Privilege Escalation by Key Rotation**  
   Enumerate credentials to determine if it's possible to rotate an administrator's credentials and assume their role.  
   - *Tools*: aws-cli, IAM analysis tools  
   - *Description*: This involves exploiting key rotation to gain administrator-level privileges by rotating the credentials of a higher-privilege user.

10. **IAM Privilege Escalation by Rollback**  
    Determine if a limited IAM user can restore a previous IAM policy that grants greater privileges to this user.  
   - *Tools*: aws-cli, custom scripts  
   - *Description*: This involves analyzing IAM policy history to determine if a rollback could grant greater privileges to a given IAM user.

11. **Unauthorized Cross-Account Access**  
   Investigate whether users can gain unauthorized cross-account access to resources in other AWS accounts.  
   - *Tools*: aws-cli, IAM policies analysis  
   - *Description*: Analyze IAM policies and permissions to identify potential cross-account access vulnerabilities.

12. **Exploiting Insecure Default Policies**  
   Test for insecure default IAM policies that grant excessive permissions to users.  
   - *Tools*: Prowler, IAM Analyzer  
   - *Description*: Prowler and IAM Analyzer can detect insecure default IAM policies and analyze user permissions for potential privilege escalation.

13. **Misconfigured EC2 IAM Roles**  
   Determine if EC2 instances are assigned overly permissive IAM roles that could be exploited for privilege escalation.  
   - *Tools*: aws-cli, EC2 metadata analysis  
   - *Description*: Query EC2 instance metadata to evaluate the permissions associated with their IAM roles.

14. **Accessing AWS Lambda Functions with Unencrypted Environment Variables**  
   Identify Lambda functions that use unencrypted environment variables, potentially exposing sensitive information.  
   - *Tools*: aws-cli, Lambda function analysis tools  
   - *Description*: Examine Lambda functions for unencrypted environment variables that may contain sensitive data.

15. **IAM Role Chain Abuse**  
   Abuse IAM role chains to escalate privileges across multiple roles and gain unauthorized access.  
   - *Tools*: aws-cli  
   - *Description*: Test the role chaining process to identify potential privilege escalation by assuming multiple roles.

16. **S3 Bucket Privilege Escalation via Policy Manipulation**  
   Manipulate S3 bucket policies to escalate privileges and gain unauthorized access to resources.  
   - *Tools*: aws-cli, S3 policy analysis  
   - *Description*: Examine S3 bucket policies for misconfigurations or manipulations that could lead to privilege escalation.

17. **CloudTrail Tampering to Obscure Logs**  
   Modify or delete CloudTrail logs to cover tracks or obscure malicious activities.  
   - *Tools*: aws-cli, custom scripts  
   - *Description*: Analyze CloudTrail logs to identify unauthorized modifications and test for tampering vulnerabilities.

18. **IAM User Enumeration via API Abuse**  
   Enumerate IAM users by abusing API endpoints that disclose information about AWS accounts.  
   - *Tools*: aws-cli, custom scripts  
   - *Description*: Use API abuse techniques to enumerate IAM users and gather sensitive information about AWS accounts.

19. **IAM Policy Escalation via Managed Policies**  
   Modify or create custom managed IAM policies to escalate privileges within an AWS account.  
   - *Tools*: aws-cli, policy editing tools  
   - *Description*: Test for privilege escalation by creating or modifying managed IAM policies to grant excessive permissions.

20. **Lambda Function Code Injection**  
    Inject code into AWS Lambda functions to gain unauthorized access or escalate privileges.  
   - *Tools*: aws-cli, custom scripts  
   - *Description*: Analyze Lambda functions for potential code injection vulnerabilities and test for privilege escalation.

# Akamai 

1. **CNAME Domain Takeover**  
   Exploit misconfigured CNAME records to gain control over domains when third-party services are withdrawn.  
   - *Tools*: DNS scanning tools, dig, nslookup  
   - *Description*: These tools allow you to scan and identify vulnerable CNAME records that can be exploited to take over domains.

2. **DNS Cache Poisoning**  
   Manipulate DNS responses to redirect users to malicious sites through Akamai's CDN.  
   - *Tools*: DNSmasq, dnsspoof  
   - *Description*: DNSmasq and dnsspoof can be used to manipulate DNS cache, allowing attackers to redirect traffic to malicious endpoints.

3. **Akamai WAF Bypass**  
   Bypass Akamai's Web Application Firewall (WAF) to execute malicious code or exploit vulnerabilities.  
   - *Tools*: custom scripts, manual testing  
   - *Description*: Test for WAF bypass techniques to identify methods of evading Akamai's security measures.

4. **Subdomain Enumeration and Takeover**  
   Enumerate Akamai-hosted subdomains and identify those vulnerable to takeover.  
   - *Tools*: Amass, Sublist3r  
   - *Description*: These tools allow you to enumerate subdomains and detect vulnerabilities that could lead to subdomain takeover.

5. **SSL/TLS Misconfiguration Exploitation**  
   Exploit insecure SSL/TLS configurations in Akamai services to intercept sensitive data.  
   - *Tools*: sslyze, OpenSSL  
   - *Description*: sslyze and OpenSSL can analyze SSL/TLS configurations to identify insecure settings that could be exploited.

6. **CDN Cache Poisoning**  
   Manipulate content cached by Akamai's CDN to serve malicious or outdated content to users.  
   - *Tools*: custom scripts, manual cache testing  
   - *Description*: Test for cache poisoning vulnerabilities to manipulate content delivered by Akamai's CDN.

7. **Credential Stuffing on Akamai Services**  
   Automate login attempts to Akamai-hosted services using breached or commonly used credentials.  
   - *Tools*: Hydra, custom scripts  
   - *Description*: Tools that automate login attempts with breached credentials to identify vulnerabilities in authentication controls.

8. **XSS on Akamai Services**  
   Inject malicious scripts into Akamai-hosted websites to manipulate user sessions or redirect users to malicious sites.  
   - *Tools*: OWASP ZAP, Burp Suite  
   - *Description*: These tools can test for and exploit Cross-Site Scripting (XSS) vulnerabilities on Akamai-hosted websites.

9. **Akamai Rate Limiting Bypass**  
   Test for methods to bypass Akamai's rate limiting to conduct brute force or Denial of Service (DoS) attacks.  
   - *Tools*: custom scripts, Burp Suite  
   - *Description*: Tools and scripts to test Akamai's rate limiting for potential bypass vulnerabilities.

10. **Malicious CDN Injection**  
    Inject malicious content into Akamai's CDN to compromise users or deliver malware.  
   - *Tools*: custom scripts, cache poisoning tools  
   - *Description*: Test for vulnerabilities that allow injection of malicious content into Akamai's CDN to compromise users.

# Email/m365 Attacks

1. **Phishing Email Delivery Bypass**  
   Test for methods to bypass M365's email security to deliver phishing emails to users' inboxes.  
   - *Tools*: Gophish, custom scripts  
   - *Description*: These tools can simulate phishing campaigns to test the effectiveness of M365's email security in preventing malicious emails.

2. **Spoofing M365 Email Headers**  
   Exploit M365 email client vulnerabilities to spoof email headers, making emails appear to come from trusted sources.  
   - *Tools*: custom scripts, email header analysis tools  
   - *Description*: These tools analyze email headers and test for methods to spoof sender information.

3. **Credential Harvesting via Email Attachments**  
   Attach malicious files to emails sent via M365 to harvest credentials from users who open them.  
   - *Tools*: custom scripts, malware analysis tools  
   - *Description*: Test for vulnerabilities in email attachment handling to exploit potential security risks.

4. **Email Account Takeover via OWA Phishing**  
   Phish users via Outlook Web App (OWA) to gain unauthorized access to their M365 email accounts.  
   - *Tools*: Gophish, Zphisher  
   - *Description*: These tools create fake OWA phishing pages to capture users' M365 credentials and gain unauthorized access.

5. **Bypassing M365 Email Authentication Mechanisms**  
   Test for vulnerabilities in email authentication to bypass security controls and send malicious emails.  
   - *Tools*: custom scripts, email authentication analysis tools  
   - *Description*: Test for methods to bypass email authentication mechanisms like SPF, DKIM, and DMARC.

6. **Email Redirection Attack**  
   Manipulate email rules or settings to redirect emails to unauthorized recipients.  
   - *Tools*: PowerShell scripts, Outlook rules analysis  
   - *Description*: These tools can analyze email rules and settings to identify vulnerabilities that could be exploited to redirect emails.

7. **Malicious Outlook Add-ins**  
   Install malicious Outlook add-ins to execute arbitrary code or collect sensitive information from M365 email clients.  
   - *Tools*: custom add-ins, malware analysis tools  
   - *Description*: Test for vulnerabilities in Outlook add-ins that could be exploited to inject malicious code.

8. **Email Bombing**  
   Send large volumes of emails to a target email account to overwhelm the M365 email client and cause Denial of Service (DoS).  
   - *Tools*: custom scripts, email automation tools  
   - *Description*: Test for methods to overwhelm M365 email clients with high volumes of emails, potentially causing a DoS attack.

9. **M365 Email Client Side Vulnerabilities**  
   Identify vulnerabilities in the M365 email client that could lead to unauthorized access or privilege escalation.  
   - *Tools*: custom scripts, security analysis tools  
   - *Description*: Test for client-side vulnerabilities that could be exploited for unauthorized access or privilege escalation.

10. **Insecure Email Forwarding Configuration**  
    Examine email forwarding settings for insecure configurations that could lead to unauthorized email forwarding.  
   - *Tools*: PowerShell scripts, custom scripts  
   - *Description*: These tools can analyze email forwarding configurations to detect vulnerabilities that could be exploited for unauthorized email forwarding.

# Thin Clients

1. **Thin Client USB Device Injection**  
   Inject malicious USB devices into thin clients to bypass security restrictions and gain unauthorized access.  
   - *Tools*: Rubber Ducky, Bash Bunny  
   - *Description*: These tools simulate USB devices that can execute malicious code on thin clients to bypass security.

2. **Remote Desktop Protocol (RDP) Vulnerabilities**  
   Exploit vulnerabilities in RDP to gain unauthorized access to thin client sessions.  
   - *Tools*: Metasploit, custom scripts  
   - *Description*: Test for known RDP vulnerabilities to determine if they can be exploited to gain unauthorized access to thin clients.

3. **Bypass Thin Client Lockdown Policies**  
   Circumvent security restrictions on thin clients to gain administrative privileges or access restricted functionalities.  
   - *Tools*: custom scripts, Group Policy Editor  
   - *Description*: Analyze thin client security policies to identify methods to bypass lockdown measures.

4. **Thin Client Network Traffic Eavesdropping**  
   Monitor and capture network traffic from thin clients to gather sensitive information.  
   - *Tools*: Wireshark, Bettercap  
   - *Description*: Tools for passive eavesdropping on network traffic to capture sensitive information from thin clients.

5. **Abusing Virtual Desktop Infrastructure (VDI)**  
   Exploit vulnerabilities in VDI environments to gain unauthorized access to thin client sessions.  
   - *Tools*: Metasploit, custom scripts  
   - *Description*: Test for vulnerabilities in VDI environments to determine potential attack vectors for thin clients.

6. **Citrix Breakout**  
   Leverage vulnerabilities within Citrix to gain access to locked-down environments.  
   - *Tools*: custom scripts, Metasploit  
   - *Description*: Test for Citrix vulnerabilities that could allow breakouts from restricted environments.

7. **Insecure Thin Client Configuration**  
   Identify misconfigurations in thin client settings that could lead to security risks.  
   - *Tools*: custom scripts, thin client management tools  
   - *Description*: Analyze thin client configurations to detect misconfigurations that could lead to security vulnerabilities.

8. **Thin Client Session Hijacking**  
   Intercept and take over thin client sessions to gain unauthorized access to the locked-down environment.  
   - *Tools*: Wireshark, RDP hijacking tools  
   - *Description*: Tools for session hijacking to gain control over thin client sessions.

9. **Breakout via Virtualization Exploits**  
   Exploit vulnerabilities in virtualization to escape the thin client environment and gain access to the underlying system.  
   - *Tools*: custom scripts, Metasploit  
   - *Description*: Test for virtualization vulnerabilities that could allow breakouts from the thin client environment.

10. **VOIP Services Exploitation**  
    Gain unauthorized access to VOIP services through thin clients.  
   - *Tools*: custom scripts, VOIP analysis tools  
   - *Description*: Analyze VOIP services used by thin clients to identify vulnerabilities that could be exploited for unauthorized access or privilege escalation.

# Jira/Confluence

1. **Recon for Poisoning Vulnerabilities**  
   Conduct reconnaissance to identify vulnerabilities in Jira/Confluence that could be exploited for cache poisoning or other attacks.  
   - *Tools*: Burp Suite, OWASP ZAP  
   - *Description*: These tools can scan for potential poisoning vulnerabilities in Jira and Confluence to manipulate cached data.

2. **Single-Factor Authentication in Confluence**  
   Test for single-factor authentication weaknesses to gain unauthorized access to Confluence.  
   - *Tools*: Burp Suite, Hydra  
   - *Description*: Tools that automate brute-force attacks to test for weak authentication controls in Confluence.

3. **Sensitive Data Extraction from Confluence**  
   Determine if sensitive data can be extracted from Confluence through insecure configurations or permissions.  
   - *Tools*: custom scripts, manual testing  
   - *Description*: Test for misconfigured permissions or public documents in Confluence that could expose sensitive information.

4. **Unauthorized Jira Ticket Access via Proxy Plugin**  
   Gain access to Jira ticket details as a non-domain user by exploiting proxy plugin vulnerabilities.  
   - *Tools*: custom scripts, proxy analysis tools  
   - *Description*: These tools can identify vulnerabilities in proxy plugins used in Jira, allowing unauthorized access to ticket details.

5. **Leaked Token Validation in Jira**  
   Test if previously leaked tokens are still valid and grant dangerous permissions in Jira.  
   - *Tools*: Burp Suite, Postman  
   - *Description*: Test for token vulnerabilities to determine if leaked tokens can still be used to gain unauthorized access.

6. **Jira Workflow Manipulation**  
   Manipulate Jira workflows to gain unauthorized permissions or perform unauthorized actions.  
   - *Tools*: custom scripts, Jira workflow analysis  
   - *Description*: Test for vulnerabilities in Jira workflows to determine if they can be exploited for privilege escalation or unauthorized actions.

7. **Confluence Page History Leakage**  
   Access sensitive information from Confluence's page history to identify potentially exploitable data.  
   - *Tools*: custom scripts, Confluence page history analysis  
   - *Description*: Test if page history can be accessed to retrieve sensitive information or previous versions of documents.

8. **Confluence Public Space Misconfiguration**  
   Exploit misconfigurations in public Confluence spaces to gain unauthorized access to sensitive data.  
   - *Tools*: custom scripts, manual testing  
   - *Description*: Test public Confluence spaces for misconfigurations that could expose sensitive information.

9. **Jira Add-On Exploitation**  
   Exploit vulnerabilities in Jira add-ons to gain unauthorized access or perform privilege escalation.  
   - *Tools*: custom scripts, add-on analysis tools  
   - *Description*: Analyze Jira add-ons to identify security vulnerabilities that could be exploited for unauthorized access or privilege escalation.

10. **Cross-Site Scripting (XSS) in Jira/Confluence**  
    Inject malicious scripts into Jira/Confluence to steal session cookies or perform other malicious activities.  
   - *Tools*: OWASP ZAP, Burp Suite  
   - *Description*: These tools can test for and exploit XSS vulnerabilities in Jira and Confluence.

11. **SQL Injection in Jira/Confluence**  
    Exploit SQL injection vulnerabilities to manipulate backend databases in Jira/Confluence.  
   - *Tools*: Sqlmap, custom scripts  
   - *Description*: Test input fields for SQL injection vulnerabilities in Jira/Confluence to manipulate backend databases.

12. **Confluence Macro Injection**  
    Inject malicious macros into Confluence pages to execute unauthorized code.  
   - *Tools*: custom scripts, macro analysis tools  
   - *Description*: Test for vulnerabilities in Confluence macros that could be exploited to execute arbitrary code.

13. **Insecure Confluence API Endpoints**  
    Identify and exploit insecure API endpoints in Confluence to extract sensitive information or perform unauthorized actions.  
   - *Tools*: Postman, Burp Suite  
   - *Description*: Test Confluence API endpoints for security vulnerabilities to determine if they can be exploited for unauthorized access.

14. **Jira Permission Escalation via Groups**  
    Manipulate Jira groups to gain additional permissions or escalate privileges.  
   - *Tools*: custom scripts, Jira group analysis tools  
   - *Description*: Test for misconfigured permissions in Jira groups to determine if they can be manipulated for privilege escalation.

15. **Confluence Privilege Escalation via Shared Access**  
    Exploit shared access permissions in Confluence to gain unauthorized privileges.  
   - *Tools*: custom scripts, Confluence permissions analysis  
   - *Description*: Analyze shared access permissions in Confluence to identify potential privilege escalation vulnerabilities.


# License

Apache License
Shubham Khichi (c) 2024
