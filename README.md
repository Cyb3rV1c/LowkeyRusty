![Screenshot 2024-11-19 at 1 45 25 PM](https://github.com/user-attachments/assets/b2dbea9f-5d14-42c5-8efd-0502a0251627)

**Description:** 
A Rust-based process injection tool leveraging XOR-encrypted payloads and dynamic API resolution for enhanced stealth.


# Features

**[+] Obfuscation Techniques:** Employs Xor decryption to avoid signature-based detection. & incorporated API obfuscation 

**[+] Process Injection** Implements process injection by dynamically resolving Windows APIs (OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThreadEx) to inject and execute XOR-encrypted shellcode in a target process.



# Getting Started


# Usage

1. Add the path to your x0r encrypted payload into the main.rs file

2. Specify Secret Key for Decryption

3. Build Cargo and Execute.

# Example Output

**Execution** 

<img width="542" alt="Screenshot 2024-11-19 at 1 53 12 PM" src="https://github.com/user-attachments/assets/73d16ad0-42c9-43e5-9493-c33f6d23a978">

<img width="542" alt="Screenshot 2024-11-19 at 1 54 06 PM" src="https://github.com/user-attachments/assets/10a080fd-4c16-4244-adfb-4eabdec69c1c">



# Disclaimer
**This project is intended for educational and research purposes only.**

The code provided in this repository is designed to help individuals understand and improve their knowledge of cybersecurity, ethical hacking, and malware analysis techniques. It must not be used for malicious purposes or in any environment where you do not have explicit permission from the owner.

