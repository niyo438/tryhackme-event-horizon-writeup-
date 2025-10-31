# tryhackme-event-horizon-writeup-
Challenge Overview
Room: Event Horizon
Category: Digital Forensics, Malware Analysis
Tools Used: Wireshark, CyberChef,ILSpy, CovenantDecryptor, TShark

Investigation Summary
Stage 1: Initial Compromise Analysis
Email Credential Discovery

Analyzed SMTP traffic in PCAP file

Identified brute-force activity around packet 4665

Found successful login with Base64-encoded credentials

Compromised Credentials: tom.dom@eventhorizon.thm:password recovered from successful authentication

Malicious Email Content

Extracted email body from TCP stream analysis

Email contained malicious instructions/attachment

Stage 2: Malware Delivery Analysis
Initial Infection Vector

Discovered Base64-encoded attachment in email

Decoded to reveal download command for radius.ps1

Located malware download at packet 4722: http://10.0.0.2.45/radius.ps1

Malware Analysis

PowerShell script contained compressed Base64 payload

Used CyberChef to decode and decompress (Raw Inflate)

Recovered PE32 executable with MZ header
<img width="2000" height="1006" alt="Screenshot 2025-10-30 204218" src="https://github.com/user-attachments/assets/47b291e5-678d-4030-bcf3-167bd0e21f6a" />

VirusTotal analysis identified Covenant C2 framework

Stage 3: C2 Communication Decryption
AES Key Extraction
<img width="1486" height="416" alt="Screenshot 2025-10-30 204402" src="https://github.com/user-attachments/assets/efc9860b-c64c-4793-8c8e-4c38774cdcee" />

Used ILSpy to decompile .NET binary

Located initial AES key in Execute Stager Class

Key Found: [AES Key] embedded in stage 0 binary
<img width="1157" height="538" alt="Screenshot 2025-10-30 210602" src="https://github.com/user-attachments/assets/04b370e7-c472-43e3-9ba6-eb5ca0e00f7e" />

Covenant Traffic Analysis

Identified 3-stage C2 communication protocol:

Stage 0: RSA session initiation

Stage 1: Session key exchange

Stage 2: Verification and data exchange

Traffic Decryption Process

Extracted POST data using TShark

Retrieved RSA private key from PowerShell memory dump

Recovered session key from stage 0 response

Decrypted C2 traffic using CovenantDecryptor tool

Stage 4: Privilege Escalation & Flag
Credential Theft

Decrypted C2 communications revealed Administrator NTLM hash

NTLM Hash: [Hash value] extracted from message traffic

Flag Extraction

Message 8 contained Base64-encoded image data

Used CyberChef to decode, revealing flag image

Flag: [THM{...}] recovered from decoded image




