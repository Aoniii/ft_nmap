# ft_nmap

[English](README.md) | 📖 **Français**

> Un scanner de ports IPv4 multithread écrit en C, qui reconstruit une partie du célèbre
> [Nmap](https://nmap.org). Il utilise des **sockets bruts (raw sockets)** pour forger ses
> propres paquets de sonde et la bibliothèque **pcap** pour capturer les réponses, puis
> affiche l'état de chaque port pour chaque type de scan. Projet de l'école 42 (`ft_nmap`).

---

## Sommaire

1. [Démarrage rapide](#démarrage-rapide)
2. [Utilisation & options](#utilisation--options)
3. [Le commutateur `POSITIONAL_TARGET`](#le-commutateur-positional_target)
4. [Partie obligatoire — ce qui est implémenté](#partie-obligatoire--ce-qui-est-implémenté)
5. [Partie bonus — flags supplémentaires](#partie-bonus--flags-supplémentaires)
6. [Comment ça marche — un cours pour débutant](#comment-ça-marche--un-cours-pour-débutant)
7. [Structure du projet](#structure-du-projet)
8. [Crédits](#crédits)

---

## Démarrage rapide

### Prérequis
- Linux (kernel > 3.14)
- `gcc`, `make`
- `libpcap` (`-lpcap`) et `pthread` (`-lpthread`)
- **privilèges root** (les sockets bruts les exigent)

```bash
# installer la dépendance si besoin (Debian/Ubuntu)
sudo apt-get install libpcap-dev

# compiler
make

# lancer (nécessite root)
sudo ./ft_nmap --ip 127.0.0.1 --ports 1-1024 --scan SYN --speedup 50
```

### Règles du Makefile
| Règle | Effet |
|-------|-------|
| `make` / `make all` | Compile `ft_nmap` (ne relink que si nécessaire) |
| `make clean` | Supprime les fichiers objets |
| `make fclean` | Supprime les objets **et** le binaire |
| `make re` | `fclean` puis recompilation complète |

---

## Utilisation & options

```
ft_nmap [OPTIONS] --ip <ip|hostname>
ft_nmap [OPTIONS] --file <fichier>
```

| Option | Argument | Description | Partie |
|--------|----------|-------------|--------|
| `--ip` | IP / hostname | Une cible unique à scanner | Obligatoire |
| `-f`, `--file` | chemin | Lit une liste de cibles depuis un fichier (séparées par des espaces) | Obligatoire |
| `-p`, `--ports` | liste/plage | Ports à scanner : `80`, `1-1024`, `80,443`, `1,5-15` (défaut `1-1024`, **max 1024**) | Obligatoire |
| `-s`, `--scan` | types | Types de scan, séparés par `/` : `SYN/NULL/ACK/FIN/XMAS/UDP` (défaut : tous) | Obligatoire |
| `--speedup` | 0–250 | Nombre de threads parallèles (`0` = mono-thread) | Obligatoire |
| `--version-detection` | — | Sonde les ports ouverts pour identifier le service/version | **Bonus** |
| `--reverse-dns` | — | Résout chaque IP en nom d'hôte (requête PTR) | **Bonus** |
| `--ttl` | 1–255 | TTL (durée de vie IP) des paquets envoyés (défaut `64`) | **Bonus** |
| `--spoof` | IP | Forge une fausse adresse source (furtif ; les réponses ne reviennent pas) | **Bonus** |
| `--open` | — | N'affiche que les ports ouverts, cache fermés/filtrés | **Bonus** |
| `--progress` | — | Tableau de bord en direct pendant le scan | **Bonus** |
| `--help` | — | Affiche l'aide et quitte | Obligatoire |

Tu peux aussi passer un **bloc CIDR** comme cible (ex. `192.168.1.0/24`) : il est développé en
chacune des adresses qu'il couvre (bonus, jusqu'à un `/16`).

### Exemples
```bash
# Scan par défaut complet d'un hôte (ports 1-1024, tous les types de scan)
sudo ./ft_nmap --ip scanme.nmap.org

# Scan SYN rapide d'une plage de ports avec 100 threads
sudo ./ft_nmap --ip 10.0.0.5 --ports 20-1024 --scan SYN --speedup 100

# Deux types de scan à la fois, n'afficher que ce qui est ouvert
sudo ./ft_nmap --ip 127.0.0.1 --ports 1-100 --scan SYN/ACK --open

# Lire les cibles depuis un fichier, identifier les services, tableau de bord en direct
sudo ./ft_nmap --file targets.txt --version-detection --progress
```

---

## Le commutateur `POSITIONAL_TARGET`

Tout en haut de `include/ft_nmap.h` se trouve un commutateur de compilation :

```c
# define POSITIONAL_TARGET  0
```

Il contrôle **la façon de passer la cible en ligne de commande**, et il faut recompiler
(`make re`) après l'avoir changé.

| Valeur | Comportement | Exemple |
|--------|--------------|---------|
| **`0`** (rendu) | Les cibles viennent **uniquement** de `--ip` ou `--file`. Un argument nu est refusé. C'est exactement l'usage exigé par le sujet. | `ft_nmap --ip 127.0.0.1` |
| **`1`** (façon nmap) | La cible est donnée en **argument positionnel**, comme le vrai `nmap`. L'option `--ip` n'existe pas dans ce mode. | `ft_nmap 127.0.0.1` |

**Pourquoi deux modes ?** Le sujet exige explicitement la forme `--ip IP_ADDRESS`, donc le
projet est rendu avec `POSITIONAL_TARGET = 0`. Le mode `= 1` est un confort qui imite le vrai
`nmap` (`nmap 127.0.0.1`) pour l'usage courant. Les deux modes sont pleinement fonctionnels
et sans fuite mémoire ; seule la manière de taper la cible change.

---

## Partie obligatoire — ce qui est implémenté

Tout ce que le sujet demande est fait :

- ✅ Exécutable nommé **`ft_nmap`** avec un vrai menu **`--help`**.
- ✅ Accepte une **adresse IPv4 ou un nom d'hôte** (FQDN accepté ; résolution déléguée au système).
- ✅ Lit une **liste de cibles depuis un fichier** (`--file`), format libre (n'importe quel espace sépare les entrées).
- ✅ **Threads** pour accélérer le scan : `--speedup`, défaut **0** (mono-thread), max **250**.
- ✅ Les six types de scan : **SYN, NULL, ACK, FIN, XMAS, UDP**.
  - Chaque type peut tourner **seul** ou **plusieurs à la fois**.
  - Si `--scan` est omis, **tous** les types sont utilisés.
- ✅ Ports donnés en **plage ou en liste** ; défaut **`1-1024`** ; limite stricte de **1024** ports.
- ✅ **Résolution du type de service** : chaque port est étiqueté avec le nom du service
  bien connu (`80 → http`, `22 → ssh`…) via la base de services du système.
- ✅ Un **résultat clair et lisible** avec le temps écoulé, en couleurs lorsque la sortie est un terminal.
- ✅ **Gestion soignée des erreurs** (aucun segfault / double free) et **aucune fuite mémoire** (vérifié avec valgrind).
- ✅ Seuls la **bibliothèque standard C**, **pcap** et **pthread** sont utilisés pour la partie obligatoire.

---

## Partie bonus — flags supplémentaires

| Flag | Catégorie bonus (du sujet) | Ce qu'il fait |
|------|----------------------------|---------------|
| `--version-detection` | Gestion DNS/Version | Se connecte à chaque port ouvert et lit sa bannière pour deviner le logiciel/version. |
| `--reverse-dns` | Gestion DNS/Version | Retransforme chaque IP en nom d'hôte (résolution DNS inverse / PTR). |
| `--ttl` | Flag pour passer l'IDS/Firewall | Permet de fixer le TTL IP des sondes (utile pour l'évasion / astuces à faible TTL). |
| `--spoof` | Cacher l'adresse source | Envoie des paquets avec une **fausse IP source** (furtif — les réponses ne te reviennent pas). |
| `--open` | Flag additionnel | N'affiche **que** les ports ouverts. |
| `--progress` | Flag additionnel | Affiche un **tableau de bord en direct** (pourcentage, temps écoulé, ETA) pendant le scan. |
| Cibles CIDR | Flag additionnel | Une cible comme `192.168.1.0/24` est développée en chaque adresse du bloc. |

---

## Comment ça marche — un cours pour débutant

*Cette section part du principe que tu n'as jamais entendu parler de « port » ni de comment
marche `ping`. Lis-la du début à la fin et, à la fin, tu comprendras chaque ligne de la sortie.*

### 1. Comment deux ordinateurs se parlent

Imagine internet comme un **système postal** :

- Une **adresse IP** (ex. `93.184.216.34`) est **l'adresse postale d'une machine**. Chaque
  ordinateur sur un réseau en possède une.
- Un **port** est comme un **numéro d'appartement à l'intérieur de ce bâtiment**. Une machine
  a 65 535 ports. Chaque programme réseau (un site web, un serveur mail, SSH…) attend ses
  visiteurs derrière un port précis — un serveur web écoute d'habitude sur le port **80**, le
  web sécurisé sur **443**, SSH sur **22**, etc. Un programme qui attend derrière un port est
  un **service**.
- Un **paquet** est une seule **lettre** : il a une adresse « **destinataire** », une adresse
  « **expéditeur** » et un contenu. Les ordinateurs n'envoient pas un flux continu ; ils
  découpent tout en paquets et les envoient un par un.

Donc « se connecter à un site web » signifie en réalité : *ma machine envoie des paquets vers
l'IP `x`, port `80`, et le serveur web là-bas renvoie des paquets vers mon IP.*

### 2. `ping` : la conversation la plus simple possible

`ping` est le « coup à la porte » du réseau. Ta machine envoie un petit paquet qui veut dire
**« es-tu vivante ? »** (une *requête ICMP echo*). Si l'autre machine est allumée, elle renvoie
**« oui, je suis là »** (une *réponse ICMP echo*). Cet aller-retour est tout ce que fait
`ping` — il ne parle à **aucun** port ni service, il vérifie juste que la machine répond.

Le scan de ports est l'étape suivante : au lieu de demander *« la machine est-elle vivante ? »*,
on demande *« la porte numéro 80 est-elle ouverte ? et la 22 ? »* — une question par port.

### 3. TCP : une vraie conversation et sa poignée de main

La plupart des services (web, SSH, mail…) parlent **TCP**. Avant d'échanger la moindre donnée,
TCP effectue une **poignée de main en 3 étapes** (*handshake*), comme un appel téléphonique :

```
Toi  ──── SYN ───▶  Serveur    « Bonjour, on peut parler ? »   (SYN = synchronize)
Toi  ◀── SYN/ACK ── Serveur    « Bien sûr, j'écoute. »          (ACK = acknowledge)
Toi  ──── ACK ───▶  Serveur    « Parfait, allons-y. »
```

Chaque paquet TCP porte un jeu de **drapeaux (flags)** activés/désactivés qui lui donnent son
sens : `SYN` (démarrer), `ACK` (accuser réception), `FIN` (terminer), `RST` (réinitialiser/refuser),
plus `PSH` et `URG`. Le scanner joue avec ces flags pour apprendre des choses **sans jamais
terminer la poignée de main**.

Deux faits utiles dont le scanner se sert :
- Si tu frappes (`SYN`) à un port **ouvert**, le service répond `SYN/ACK`.
- Si tu envoies **n'importe quoi** à un port **fermé**, la machine claque la porte avec un `RST`
  (« reset — il n'y a personne »).

### 4. Ce qu'est réellement le « scan de ports »

Le scanner **forge des paquets à la main**, les envoie vers un port cible et **observe comment
la cible réagit**. La réaction (un `SYN/ACK`, un `RST`, une erreur, ou le *silence*) nous dit si
le port est ouvert, fermé, ou caché derrière un pare-feu. Les différents **types de scan**
envoient différentes combinaisons de flags pour extraire différentes informations.

### 5. Comment ft_nmap envoie et écoute

Deux outils bas niveau rendent cela possible :

- **Socket brut (raw socket)** (pour *envoyer*) : un programme normal laisse le système
  d'exploitation construire les en-têtes des paquets à sa place. Un **socket brut** nous laisse
  écrire **nous-mêmes les en-têtes IP et TCP**, octet par octet — c'est ainsi qu'on peut poser
  des flags arbitraires, une fausse source, un TTL personnalisé, etc. Construire des paquets à la
  main est une opération privilégiée, et c'est pourquoi **ft_nmap doit tourner en root** (`sudo`).
- **pcap / filtre BPF** (pour *écouter*) : les réponses n'arrivent pas commodément sur notre
  socket, alors on utilise la bibliothèque **pcap** pour renifler directement la carte réseau et
  les attraper. Un **filtre BPF** dit à pcap « montre-moi seulement les paquets qui reviennent de
  cette cible, visant mes ports de sonde », pour ignorer tout le trafic sans rapport.

Pour associer une réponse à la bonne sonde, chaque type de scan émet depuis un **port source
distinct**, et pcap vérifie que la réponse est bien adressée à ce port exact.

### 6. Les types de scan, et comment lire les réponses

Chaque scan envoie une sonde et classe le port selon ce qui revient (ou selon le **silence**,
qui est lui-même un indice). Voici exactement ce que fait ft_nmap :

| Scan | Ce qu'il envoie | Réponse → verdict |
|------|-----------------|-------------------|
| **SYN** | un `SYN` seul (poignée de main « à moitié ouverte ») | `SYN/ACK` → **ouvert** · `RST` → **fermé** · rien → **filtré** |
| **NULL** | un paquet **sans aucun flag** | `RST` → **fermé** · rien → **ouvert\|filtré** |
| **FIN** | uniquement le flag `FIN` | `RST` → **fermé** · rien → **ouvert\|filtré** |
| **XMAS** | `FIN`+`PSH`+`URG` (allumé « comme un sapin de Noël ») | `RST` → **fermé** · rien → **ouvert\|filtré** |
| **ACK** | uniquement le flag `ACK` | `RST` → **non filtré** · rien → **filtré** |

Pourquoi ils se comportent différemment :

- **Le scan SYN** est le classique. Il démarre une poignée de main mais **ne la termine jamais**
  (il n'envoie jamais l'`ACK` final), donc la connexion n'est jamais complètement établie — d'où
  le nom « à moitié ouverte » (*half-open*) et un côté plus furtif qu'une vraie connexion.
- **NULL / FIN / XMAS** exploitent une règle de TCP : un port **fermé** doit répondre `RST` à un
  paquet bizarre, tandis qu'un port **ouvert** est tenu de **rester silencieux**. Donc *le silence
  signifie que le port est probablement ouvert* — mais le silence peut aussi vouloir dire qu'un
  pare-feu a mangé le paquet, d'où le verdict honnête **ouvert|filtré** (« ouvert ou filtré,
  impossible d'être sûr »). Ces scans passent aussi à travers certains pare-feux simples qui ne
  guettent que les `SYN`.
- **Le scan ACK** ne parle pas du tout d'ouvert/fermé — il **cartographie le pare-feu**. Si un
  `RST` revient, le paquet a atteint l'hôte : le port est **non filtré** (aucun pare-feu ne le
  bloque). Si rien ne revient, un pare-feu l'a discrètement jeté : **filtré**.

### 7. Le scan UDP (une autre bête)

**UDP** n'a ni poignée de main ni flags — tu tires un datagramme et tu espères. La logique est
donc inversée et repose sur **ICMP** (la même famille de protocole que `ping`) :

| Réponse | Verdict |
|---------|---------|
| Un **ICMP « port injoignable »** (type 3, code 3) | **fermé** |
| Une vraie **réponse UDP** depuis le port | **ouvert** |
| Un autre ICMP injoignable (codes 1, 2, 9, 10, 13) | **filtré** |
| **Rien**, même après plusieurs tentatives | **ouvert\|filtré** |

Comme le noyau **limite le débit** de ces messages ICMP « fermé », ft_nmap **retransmet** chaque
sonde UDP plusieurs fois avant d'abandonner — c'est pour ça que les scans UDP sont plus lents.

### 8. Les états des ports, en clair

| État | Signification |
|------|---------------|
| **Ouvert** | Un service écoute et a répondu. |
| **Fermé** | La machine est joignable mais rien n'écoute sur ce port. |
| **Filtré** | Un pare-feu jette silencieusement la sonde ; impossible de savoir ce qu'il y a derrière. |
| **Non filtré** | (scan ACK) Le port est joignable — pas de pare-feu — mais on ne peut pas distinguer ouvert de fermé. |
| **Ouvert\|Filtré** | Soit ouvert, soit filtré ; le type de scan ne peut pas trancher. |

Quand plusieurs types de scan sont lancés sur le même port, ft_nmap les combine en une seule
**conclusion** (un « ouvert » de n'importe quel scan l'emporte).

### 9. Pourquoi les threads accélèrent tout

Scanner un port, c'est *envoyer, puis attendre jusqu'à quelques secondes une réponse*. Faire
1024 ports × 6 types de scan les uns après les autres serait atrocement lent, parce que le plus
clair du temps est passé à **attendre**. Alors ft_nmap construit une **file de tâches** où chaque
job est une paire `(port, type de scan)`. Avec `--speedup N`, **N threads ouvriers** piochent
chacun des jobs dans la file et scannent en parallèle — pendant qu'un thread attend une réponse,
les autres continuent de travailler. Les résultats sont écrits dans des cases séparées, donc
aucun thread ne marche jamais sur les données d'un autre.

### 10. Les noms de service

Enfin, pour chaque port ft_nmap cherche le **service bien connu** associé au numéro de port (via
la base de services du système) et l'affiche — `80 → http`, `22 → ssh`, `53 → domain`… C'est la
« résolution des types de service » demandée par le sujet. L'option `--version-detection` va plus
loin : elle se connecte réellement aux ports ouverts et lit leur bannière pour deviner le
**logiciel et la version exacts**.

---

## Structure du projet

```
ft_nmap/
├── Makefile            Règles de compilation (ne relink que si nécessaire)
├── source.mk           Liste des fichiers sources de src/
├── include/            En-têtes publics (ft_nmap.h, config.h, network.h, worker.h, display.h)
├── src/                Le scanner
│   ├── main.c              Table des options CLI + point d'entrée
│   ├── build_config.c      Valide les arguments bruts en une config utilisable
│   ├── parse_port.c        Parse la liste/plage de --ports
│   ├── parse_scan.c        Parse le masque de bits de --scan
│   ├── build_target.c      Construit la liste des cibles (--ip / --file)
│   ├── cidr.c              Développe les blocs CIDR en cibles
│   ├── network.c           Socket brut + configuration interface / pcap
│   ├── forge_packet.c      Construit à la main les en-têtes IP/TCP/UDP
│   ├── checksum.c          Checksum internet (RFC 1071)
│   ├── send_packet.c       Envoie un paquet forgé
│   ├── set_filter.c        Compile le filtre de capture BPF
│   ├── scan_one.c          Envoie une sonde et interprète la réponse
│   ├── worker.c            Routine de thread : pioche les jobs dans la file
│   ├── nmap.c              Orchestration (prepare → scan de chaque cible → cleanup)
│   ├── show.c              Met en forme les résultats
│   ├── progress.c          Le tableau de bord --progress
│   ├── version_detect.c    Récupération de bannière --version-detection
│   ├── reverse_dns.c       Résolution PTR --reverse-dns
│   └── ...                 (helpers : IP source, taille d'en-tête de lien, flags…)
└── parser/             Parseur d'arguments en ligne de commande autonome (avec son propre README)
```

