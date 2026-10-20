# tcpreplay Windows native

Implémentation Windows native de la suite tcpreplay 4.6, construite avec Visual Studio 2019/CMake et utilisant Npcap pour l’injection réseau.

## Bibliothèque C/C++ et Python

Le port Windows fournit une ABI C stable dans
`include/tcpreplay/tcpreplay_api.h` :

- `libtcpreplay.dll` et `libtcpreplay.lib` (bibliothèque d’importation) ;
- `libtcpreplay_static.lib` pour l’édition de liens statique ;
- `examples/libtcpreplay.cpp` pour C/C++ ;
- `examples/libtcpreplay.py` pour Python avec `ctypes`.

L’appel `tcpreplay_run()` est synchrone. Un autre thread peut appeler
`tcpreplay_stop()` et consulter `tcpreplay_get_stats()` pendant le rejeu.
Le mode `tcpreplay_set_output_pcap()` permet de tester l’intégration sans
envoyer de trafic sur le réseau.

Le guide complet d’installation, de liaison et d’utilisation est disponible
dans [docs/LIBTCPREPLAY.md](docs/LIBTCPREPLAY.md).

## Outils

### tcpreplay

Rejoue une ou plusieurs captures sur une interface Npcap. Il gère notamment les cadences, boucles, sélections de paquets, statistiques, pertes simulées, doubles interfaces, caches `tcpprep` v04 et la sortie PCAP.

```powershell
tcpreplay.exe --intf1 2 --pps 1000 capture.pcap
```

### tcpreplay-edit

Possède toutes les options de `tcpreplay` et ajoute la réécriture à la volée.

```powershell
tcpreplay-edit.exe --intf1 2 --dst-ip 10.0.0.5 --dport 8080 capture.pcap
```

Options de réécriture actuellement disponibles : `--src-ip`, `--dst-ip`, `--sport` et `--dport`. Les checksums IPv4, TCP et UDP sont recalculés.

### tcprewrite

Transforme une capture hors ligne, sans ouvrir Npcap.

```powershell
tcprewrite.exe --infile capture.pcap --outfile resultat.pcap --dst-ip 10.0.0.5
```

Le fichier de sortie doit être différent du fichier d’entrée.

## Compilation Visual Studio 2019

```powershell
cmake -S . -B build-vs2019 -G "Visual Studio 16 2019" -A x64
cmake --build build-vs2019 --config Release --parallel
```

Les exécutables et `libtcpreplay.dll` sont produits dans
`build-vs2019/bin/Release`. Les fichiers `.lib` sont placés dans
`build-vs2019/lib/Release`.

Pour installer les bibliothèques, le header et l’exemple Python dans un
répertoire redistribuable :

```powershell
cmake --install build-vs2019 --config Release --prefix dist
```

Le projet historique `tcpreplay.sln` continue à construire `tcpreplay.exe`. CMake est le build principal pour la suite complète.

## Architecture

- `packet_edit.*` : transformations et checksums ;
- `rewrite_cli.*` : validation commune des options de transformation ;
- `pcap_source.*` : streaming, préchargement et dual-file ;
- `tcpprep_cache.*` : lecture des caches `tcpprep` v04 ;
- `tcpreplay_api.cpp` et `include/tcpreplay/tcpreplay_api.h` : API C publique ;
- `main.cpp` : moteur et CLI de `tcpreplay`/`tcpreplay-edit` ;
- `tcprewrite.cpp` : outil de transformation hors ligne.

Le projet est distribué sous les conditions de la GPLv3, conformément au projet tcpreplay de référence.
