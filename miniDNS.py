
import socket
import threading
import configparser
import argparse
import logging
import time
import struct
import os
import re
import urllib.request
from urllib.parse import urlparse
from datetime import datetime

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('dns_server')

# Classe pour gérer les requêtes DNS
class DNSQuery:
    def __init__(self, data):
        self.data = data
        self.domain = ''
        
        # Analyse de l'en-tête DNS
        header = struct.unpack('!HHHHHH', data[:12])
        self.transaction_id = header[0]
        self.flags = header[1]
        
        # Type de requête (Questions count)
        self.questions_count = header[2]
        
        # Extraction du nom de domaine
        tipo = (data[2] >> 3) & 15  # Type de requête
        if tipo == 0:  # Standard query
            ini = 12
            lon = data[ini]
            while lon != 0:
                self.domain += data[ini + 1:ini + lon + 1].decode('utf-8') + '.'
                ini += lon + 1
                lon = data[ini]
            if self.domain:
                self.domain = self.domain[:-1]  # Remove last dot
    
    def response(self, ip):
        packet = b''
        if self.domain:
            # En-tête de réponse
            packet += self.data[:2]  # Transaction ID
            packet += struct.pack('!H', 0x8180)  # Flags: QR=1, AA=1, RA=1
            packet += self.data[4:6]  # Questions count
            packet += struct.pack('!H', 1)  # Answer count
            packet += struct.pack('!H', 0)  # Authority count
            packet += struct.pack('!H', 0)  # Additional count
            
            # Question section (recopie de la requête)
            query_end = 12
            while query_end < len(self.data) and self.data[query_end] != 0:
                query_end += self.data[query_end] + 1
            query_end += 5  # Skip 0x00 and QTYPE/QCLASS
            packet += self.data[12:query_end]
            
            # Answer section
            packet += b'\xc0\x0c'  # Pointer to domain name
            packet += struct.pack('!H', 1)  # Type A
            packet += struct.pack('!H', 1)  # Class IN
            packet += struct.pack('!I', 60)  # TTL (60 seconds)
            packet += struct.pack('!H', 4)  # Data length (4 bytes for IPv4)
            
            # IPv4 address
            for part in ip.split('.'):
                packet += struct.pack('!B', int(part))
                
        return packet

class DNSServer:
    def __init__(self, config_file='config.ini'):
        self.config_file = config_file
        self.hosts_file = None
        self.hosts = {}
        self.primary_dns = None
        self.secondary_dns = None
        self.reload_interval = 0
        self.load_config()
        
        # Chargement initial du fichier hosts s'il est défini
        if self.hosts_file:
            self.load_hosts()
        
    def load_config(self):
        """Charge la configuration depuis le fichier config.ini"""
        if not os.path.exists(self.config_file):
            logger.error(f"Le fichier de configuration {self.config_file} n'existe pas!")
            raise FileNotFoundError(f"Le fichier {self.config_file} n'existe pas!")
            
        config = configparser.ConfigParser()
        config.read(self.config_file)
        
        # Récupération des serveurs DNS
        if 'DNS' in config:
            self.primary_dns = config['DNS'].get('primary', '8.8.8.8').strip()
            self.secondary_dns = config['DNS'].get('secondary', '8.8.4.4').strip()
            logger.info(f"Serveurs DNS configurés : primaire={self.primary_dns}, secondaire={self.secondary_dns}")
        else:
            self.primary_dns = '8.8.8.8'  # Google DNS par défaut
            self.secondary_dns = '8.8.4.4'
            logger.warning("Section DNS non trouvée, utilisation des serveurs par défaut")
        
        # Récupération des paramètres de configuration du fichier hosts
        if 'HOSTS_CONFIG' in config:
            # Chemin vers le fichier hosts (local ou URL)
            hosts_path = config['HOSTS_CONFIG'].get('path', None)
            if hosts_path:
                # Nettoyer et traiter la chaîne de caractères
                raw_path = hosts_path.strip()
                # Supprimer les commentaires éventuels
                if '#' in raw_path:
                    raw_path = raw_path[:raw_path.find('#')].strip()
                
                self.hosts_file = raw_path
                logger.info(f"Fichier hosts configuré : {self.hosts_file}")
            else:
                self.hosts_file = None
                logger.info("Aucun fichier hosts configuré")
            
            # Intervalle de rechargement du fichier hosts
            try:
                self.reload_interval = int(config['HOSTS_CONFIG'].get('reload_interval', '0').strip())
                if self.reload_interval > 0:
                    logger.info(f"Intervalle de rechargement du fichier hosts : {self.reload_interval} secondes")
                else:
                    logger.info("Rechargement automatique du fichier hosts désactivé")
            except ValueError:
                logger.warning("Valeur d'intervalle de rechargement invalide, désactivation du rechargement automatique")
                self.reload_interval = 0
    
    def is_url(self, path):
        """Vérifie si le chemin donné est une URL"""
        return path and path.startswith(('http://', 'https://'))
    
    def read_hosts_content(self):
        """Lit le contenu du fichier hosts, que ce soit depuis un fichier local ou une URL"""
        if not self.hosts_file:
            logger.warning("Aucun fichier hosts configuré")
            return []
            
        if self.is_url(self.hosts_file):
            try:
                # Extraire l'URL proprement sans le commentaire
                url = self.hosts_file.split('#')[0].strip()
                logger.info(f"Téléchargement du fichier hosts depuis {url}")
                with urllib.request.urlopen(url, timeout=10) as response:
                    content = response.read().decode('utf-8')
                logger.info(f"Fichier hosts téléchargé avec succès depuis {url}")
                return content.splitlines()
            except urllib.error.URLError as e:
                logger.error(f"Erreur lors du téléchargement du fichier hosts: {e}")
                return []
            except Exception as e:
                logger.error(f"Erreur inattendue lors du téléchargement du fichier hosts: {e}")
                return []
        else:
            # Fichier local
            if not os.path.exists(self.hosts_file):
                logger.warning(f"Le fichier hosts {self.hosts_file} n'existe pas. Aucun mapping local ne sera utilisé.")
                return []
                
            try:
                with open(self.hosts_file, 'r', encoding='utf-8') as f:
                    return f.readlines()
            except Exception as e:
                logger.error(f"Erreur lors de la lecture du fichier hosts: {e}")
                return []
    
    def load_hosts(self):
        """Charge les mappages depuis le fichier hosts au format Windows (local ou URL)"""
        lines = self.read_hosts_content()
        if not lines:
            return
        
        # Réinitialiser les mappages d'hôtes
        self.hosts = {}
            
        # Parse du fichier hosts (format Windows)
        for line in lines:
            # Retrait des commentaires (commence par # ou après un #)
            if '#' in line:
                line = line[:line.index('#')]
            
            # Ignorer les lignes vides
            line = line.strip()
            if not line:
                continue
            
            # Split par espaces ou tabulations et filtrer les éléments vides
            parts = [part for part in re.split(r'\s+', line) if part]
            
            if len(parts) >= 2:
                ip = parts[0]
                # Validation basique de l'IP
                if not self._is_valid_ip(ip):
                    logger.warning(f"IP invalide ignorée: {ip}")
                    continue
                    
                # Récupération des domaines associés à cette IP
                domains = parts[1:]
                for domain in domains:
                    domain = domain.lower()
                    self.hosts[domain] = ip
                    logger.debug(f"Hôte chargé: {domain} -> {ip}")
        
        if self.hosts_file:
            logger.info(f"{len(self.hosts)} entrées d'hôtes chargées depuis {self.hosts_file}")
    
    def _is_valid_ip(self, ip):
        """Vérifie si une chaîne est une adresse IPv4 valide"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            return all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    def forward_dns_query(self, query_data, dns_server):
        """Transmet une requête DNS à un serveur DNS externe"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)  # 3 secondes de timeout
            sock.sendto(query_data, (dns_server, 53))
            response, _ = sock.recvfrom(1024)
            return response
        except socket.timeout:
            logger.warning(f"Timeout lors de la requête au serveur DNS {dns_server}")
            return None
        except Exception as e:
            logger.error(f"Erreur lors de la requête au serveur DNS {dns_server}: {e}")
            return None
        finally:
            sock.close()

    def process_request(self, data, client_address):
        """Traite une requête DNS reçue"""
        query = DNSQuery(data)
        domain = query.domain.lower()
        
        if not domain:
            logger.warning(f"Requête DNS invalide reçue de {client_address}")
            return None
            
        logger.info(f"Requête pour {domain} de {client_address[0]}:{client_address[1]}")
        
        # Vérification si le domaine est dans notre fichier hosts
        if domain in self.hosts:
            ip = self.hosts[domain]
            logger.info(f"Correspondance trouvée dans le fichier hosts: {domain} -> {ip}")
            return query.response(ip)
        
        # Essai avec le serveur DNS primaire
        logger.debug(f"Transmission de la requête au serveur DNS primaire {self.primary_dns}")
        response = self.forward_dns_query(data, self.primary_dns)
        
        # Si pas de réponse, essai avec le serveur DNS secondaire
        if response is None and self.secondary_dns:
            logger.debug(f"Échec du primaire, essai avec le serveur DNS secondaire {self.secondary_dns}")
            response = self.forward_dns_query(data, self.secondary_dns)
        
        return response
    
    def handle_client(self, data, client_socket, client_address):
        """Gère une connexion client"""
        try:
            start_time = time.time()
            response = self.process_request(data, client_address)
            
            if response:
                client_socket.sendto(response, client_address)
                logger.info(f"Réponse envoyée à {client_address[0]}:{client_address[1]} "
                           f"en {(time.time() - start_time)*1000:.2f}ms")
            else:
                logger.warning(f"Pas de réponse générée pour {client_address[0]}:{client_address[1]}")
        except Exception as e:
            logger.error(f"Erreur lors du traitement de la requête de {client_address}: {e}")
    
    def start(self, ip='0.0.0.0', port=53):
        """Démarrage du serveur DNS"""
        try:
            # Mise en place du rechargement automatique du fichier hosts si configuré
            if self.hosts_file and self.reload_interval > 0:
                def reload_hosts_periodically():
                    while True:
                        time.sleep(self.reload_interval)
                        logger.info(f"Rechargement du fichier hosts {self.hosts_file}")
                        self.load_hosts()
                
                reload_thread = threading.Thread(target=reload_hosts_periodically)
                reload_thread.daemon = True
                reload_thread.start()
                logger.info(f"Rechargement automatique du fichier hosts configuré toutes les {self.reload_interval} secondes")
            
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((ip, port))
            logger.info(f"Serveur DNS démarré sur {ip}:{port}")
            logger.info(f"Utilisation des serveurs DNS: primaire={self.primary_dns}, secondaire={self.secondary_dns}")
            
            if self.hosts_file:
                source_type = "URL distante" if self.is_url(self.hosts_file) else "fichier local"
                logger.info(f"{len(self.hosts)} entrées dans le fichier hosts ({source_type})")
            else:
                logger.info("Aucun fichier hosts configuré")
            
            while True:
                try:
                    data, client_address = server_socket.recvfrom(1024)
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(data, server_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except Exception as e:
                    logger.error(f"Erreur lors de la réception d'une requête: {e}")
        except PermissionError:
            logger.error(f"Permission refusée pour le port {port}. Essayez d'exécuter le script en tant qu'administrateur.")
        except OSError as e:
            if e.errno == 98:  # Adresse déjà utilisée
                logger.error(f"Le port {port} est déjà utilisé par un autre processus.")
            else:
                logger.error(f"Erreur lors du démarrage du serveur: {e}")
        except KeyboardInterrupt:
            logger.info("Arrêt du serveur DNS")
        finally:
            if 'server_socket' in locals():
                server_socket.close()

def main():
    parser = argparse.ArgumentParser(description='Serveur DNS léger')
    parser.add_argument('-c', '--config', default='config.ini', help='Chemin vers le fichier de configuration')
    parser.add_argument('-p', '--port', type=int, default=53, help='Port d\'écoute (défaut: 53)')
    parser.add_argument('-i', '--ip', default='0.0.0.0', help='Adresse IP d\'écoute (défaut: 0.0.0.0)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Mode verbeux')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        server = DNSServer(args.config)
        server.start(args.ip, args.port)
    except FileNotFoundError as e:
        logger.error(e)
        print(f"Erreur: {e}")
        print(f"Veuillez créer un fichier de configuration {args.config} avec la section [DNS]")
        exit(1)

if __name__ == "__main__":
    main()
