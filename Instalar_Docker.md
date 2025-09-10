                                           
┌──(kali㉿kali)-[~/Documents]
└─$ sudo apt update


┌──(kali㉿kali)-[~/Documents]
└─$ sudo apt install -y docker.io



┌──(kali㉿kali)-[~/Documents]
└─$ sudo systemctl enable docker --now
Synchronizing state of docker.service with SysV service script with /usr/lib/systemd/systemd-sysv-install.
Executing: /usr/lib/systemd/systemd-sysv-install enable docker


┌──(kali㉿kali)-[~/Documents]
└─$  sudo usermod -aG docker $USER


┌──(kali㉿kali)-[~/Documents]
└─$ sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
100 12.1M  100 12.1M    0     0  3334k      0  0:00:03  0:00:03 --:--:-- 3736k


┌──(kali㉿kali)-[~/Documents]
└─$ sudo chmod +x /usr/local/bin/docker-compose
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents]
└─$ docker-compose --version
docker-compose version 1.29.2, build 5becea4c
                                                                                                                                                                      










                                                                                                                                                                      -----------------------------------------------------

                                                                                                                                                                      