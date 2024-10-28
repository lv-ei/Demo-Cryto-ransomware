# Overview:
Demo-Crypto-Ransomware is a security demonstration project designed to showcase the core techniques used in encryption-based ransomware. By using a combination of AES (Advanced Encryption Standard) and RSA (Rivest-Shamir-Adleman) algorithms, this demo simulates how ransomware encrypts files in a specified directory on a target system. This can be a helpful study tool for cybersecurity students, analysts, and ethical hackers looking to understand the underlying encryption mechanisms and functionality in a controlled environment.

# How It Works
- Step 1: File Scanning: The script begins by scanning a specified directory, identifying files targeted for encryption.

- Step 2: AES Encryption: Each file is encrypted using the AES algorithm. AES provides fast and secure encryption for individual files, making it the preferred choice for ransomware aiming to encrypt large numbers of files quickly.

- Step 3: RSA Key Pair Generation: The script generates an RSA key pair (public and private keys). While the AES key is used for actual file encryption, the RSA public key is employed to encrypt this AES key securely.

- Step 4: AES Key Encryption: The AES encryption key, now encrypted with the RSA public key, is stored within the system. Only with the RSA private key can this AES key be decrypted, which simulates the ransom demand phase of ransomware attacks.

- Step 5: Decryption Process: A decryption script requires the RSA private key to retrieve the AES key, which can then decrypt the files in their original state.

# Technology Stack
- Python: The primary language used to handle encryption and file I/O operations.
- Cryptography Library: To implement AES and RSA encryption standards.
- User Interface: Minimalistic command-line interface designed to keep interactions simple and clear.
  
# Features
- Recursive Directory Encryption: Encrypts all files within a specified directory, including subfolders.
- AES + RSA Hybrid Encryption: Combines the strengths of AES for file encryption and RSA for secure key transfer.
- Error Handling: Handles file access permissions and file type limitations gracefully.
- Simulated Ransom Note: An optional feature to display a simulated ransom note after encryption.
  
# Important Notices
This project is strictly for demonstration and educational purposes. Misuse of ransomware is illegal and can have severe consequences. This code should not be deployed on any unauthorized systems or environments. Ethical use only
