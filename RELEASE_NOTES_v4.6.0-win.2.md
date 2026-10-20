# tcpreplay 4.6.0-win.2

Cette version ajoute une API C publique et les bibliothèques permettant
d’embarquer le moteur de rejeu Windows natif dans une application.

## Nouveautés

- `libtcpreplay.dll` et sa bibliothèque d’importation `libtcpreplay.lib` ;
- bibliothèque statique `libtcpreplay_static.lib` ;
- header public `tcpreplay/tcpreplay_api.h` avec ABI C ;
- utilisation depuis C++ et Python `ctypes` ;
- rejeu vers une interface Npcap ou écriture dans un PCAP ;
- vitesses capture, maximum, PPS, Mbps et multiplicateur ;
- boucles, limite de paquets, durée maximale et choix du timer ;
- arrêt inter-thread et statistiques consultables en direct ;
- installation CMake des bibliothèques, headers et exemple Python ;
- guide complet dans `docs/LIBTCPREPLAY.md`.

## Archive Windows x64

Elle contient les trois exécutables, la DLL, les deux `.lib`, le header public,
les exemples C++ et Python, la documentation et ces notes de version.

Npcap doit être installé sur la machine cible. L’injection réseau peut exiger
des droits administrateur.
