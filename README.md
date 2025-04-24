
# MiniDNS - Serveur DNS Léger

MiniDNS est un serveur DNS léger et configurable écrit en Python. Il permet de gérer des requêtes DNS en utilisant un fichier hosts local ou distant, avec transfert vers des serveurs DNS externes pour les domaines non résolus localement.

## Fonctionnalités

- Serveur DNS complet fonctionnant sur le port 53 (par défaut)
- Support des fichiers hosts locaux et distants
- Rechargement automatique du fichier hosts à intervalle configurable
- Transfert des requêtes non résolues vers des serveurs DNS primaires/secondaires
- Logging détaillé des opérations

## Prérequis

- Python 3.6 ou supérieur
- Bibliothèques standard Python (pas de dépendances externes)

## Installation

### Depuis les sources

1. Clonez ce dépôt :
   ```
   git clone https://github.com/votre-username/minidns.git
   cd minidns
   ```

2. Exécutez directement le script :
   ```
   python miniDNS.py
   ```

### Version exécutable

Vous pouvez utiliser l'exécutable précompilé disponible dans les releases.

⚠️ **Important** : L'exécutable doit être placé dans un répertoire contenant le fichier `config.ini`.

## Configuration

MiniDNS utilise un fichier `config.ini` pour sa configuration. Ce fichier **doit être placé dans le même répertoire que l'exécutable** ou le script Python.

### Exemple de config.ini

```ini
[DNS]
primary = 1.1.1.1
secondary = 8.8.8.8

[HOSTS_CONFIG]
# Chemin vers le fichier hosts local ou URL
path = https://example.com/hosts
# Ou un fichier local:
# path = hosts
# Intervalle de rechargement automatique du fichier hosts en secondes
# 0 = pas de rechargement automatique
reload_interval = 15
```

### Format du fichier hosts

Le fichier hosts suit le format standard :
```
# Commentaire
192.168.1.10 exemple.com www.exemple.com
192.168.1.20 autre-exemple.com
```

Il peut être soit un fichier local, soit accessible via une URL.

## Utilisation

### Options de ligne de commande

```
python miniDNS.py [-h] [-c CONFIG] [-p PORT] [-i IP] [-v]
```

Options :
- `-h, --help` : Affiche l'aide
- `-c CONFIG, --config CONFIG` : Chemin vers le fichier de configuration (défaut: config.ini)
- `-p PORT, --port PORT` : Port d'écoute (défaut: 53)
- `-i IP, --ip IP` : Adresse IP d'écoute (défaut: 0.0.0.0)
- `-v, --verbose` : Mode verbeux

### Exécution en tant qu'administrateur

Le port 53 étant un port privilégié, vous devrez exécuter le script en tant qu'administrateur sous Linux/macOS :

```
sudo python miniDNS.py
```

Sous Windows, exécutez l'invite de commandes ou PowerShell en tant qu'administrateur.

### Utilisation de l'exécutable

```
./MiniDNS [-h] [-c CONFIG] [-p PORT] [-i IP] [-v]
```

⚠️ **Rappel** : Assurez-vous que le fichier `config.ini` se trouve dans le même répertoire que l'exécutable.

## Compilation

Pour compiler le script en exécutable, utilisez PyInstaller :

```
pyinstaller --onefile --exclude-module config.ini --exclude-module hosts --name MiniDNS miniDNS.py
```

Cette commande crée un exécutable autonome qui recherchera le fichier config.ini dans son répertoire d'exécution.

## miniDNS en service

Si vous souhaitez utiliser ce programme en service sou swindows, installez-le à l'aide de NSSM https://nssm.cc/download, c'est simple et rapide.

-Executez nssm install nomdevotreservice

-Suivez les instructions en pointant l'executable miniDNS.exe

## Dépannage

### Erreurs communes

- **Permission refusée pour le port 53** : Exécutez le script en tant qu'administrateur
- **Le port 53 est déjà utilisé** : Vérifiez s'il n'y a pas déjà un serveur DNS en cours d'exécution
- **Fichier hosts introuvable** : Vérifiez le chemin dans config.ini
- **Erreur lors du téléchargement du fichier hosts** : Vérifiez l'URL dans config.ini

## Licence

Ce projet est distribué sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.
