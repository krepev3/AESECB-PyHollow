# AESECB-PyHollow
Process Hollowing using Python and AESECB Encryption

===================================
            Process Hollowing with AES
===================================

Description:
-------------
This Python project demonstrates process hollowing in a 64-bit Windows environment using a 32-bit Notepad process. The payload (Executor.exe) is encrypted using AES (ECB mode) and injected into a suspended Notepad process after decryption.

Main Features:
--------------
- AES encryption and decryption using the PyCrypto library (AES.MODE_ECB)
- Encrypts a payload (Executor.exe) into a secure form (Executor.enc)
- Performs process hollowing by injecting the decrypted payload into Notepad.exe
- Supports thread context manipulation, memory allocation, and payload injection

Requirements:
-------------
- Python 3.x
- PyCrypto (install via `pip install pycryptodome`)
- psutil (install via `pip install psutil`)
- pywin32 (install via `pip install pywin32`)
- Administrator privileges for process injection

File Structure:
---------------
- executor_path                -> Path to the original payload (Executor.exe)
- encrypted_path               -> Path to store the encrypted payload (Executor.enc)
- main.py                      -> Main Python script containing the logic for encryption and process hollowing

AES Key:
--------
The AES encryption key is hardcoded for demonstration:
"Sixteen byte key"

Note: ECB mode is used for simplicity, but it is not recommended for real-world applications due to security concerns. Avoid using static keys.

Disclaimer:
-----------
This code is intended strictly for educational and research purposes. 
It should not be used against machines or systems that you do not have explicit permission to test.

Created by: Lyxt
Year: 2025
