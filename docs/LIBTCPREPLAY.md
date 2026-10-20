# Utiliser libtcpreplay sous Windows

`libtcpreplay` expose le moteur de rejeu sous la forme d’une ABI C, utilisable
depuis C, C++, Python avec `ctypes`, ou tout langage capable de charger une DLL.

La version `4.6.0-win.2` fournit :

- `bin/libtcpreplay.dll` : bibliothèque dynamique x64 ;
- `lib/libtcpreplay.lib` : bibliothèque d’importation MSVC de la DLL ;
- `lib/libtcpreplay_static.lib` : bibliothèque statique MSVC ;
- `include/tcpreplay/tcpreplay_api.h` : API C publique ;
- `bin/libtcpreplay.py` : exemple Python.

## Prérequis

- Windows 10 ou plus récent en x64 ;
- Npcap installé, de préférence en mode compatible WinPcap ;
- Visual Studio 2019 ou compatible pour une application C/C++.

La sortie vers un PCAP n’envoie aucun trafic et convient aux premiers tests.
L’injection réseau peut nécessiter une console avec les droits administrateur.

## Construction et installation

```powershell
cmake -S . -B build -G "Visual Studio 16 2019" -A x64
cmake --build build --config Release --parallel
cmake --install build --config Release --prefix dist
```

La DLL est installée sous `dist/bin`, les `.lib` sous `dist/lib` et le header
sous `dist/include/tcpreplay`.

## C++ avec la bibliothèque statique

Définir `TCPREPLAY_STATIC` avant le header, puis lier `libtcpreplay_static.lib`,
`wpcap.lib`, `Packet.lib` et `ws2_32.lib`. Le target CMake propage ces éléments :

```cmake
add_subdirectory(tcpreplay)
add_executable(mon_replay main.cpp)
target_link_libraries(mon_replay PRIVATE libtcpreplay_static)
```

Exemple minimal :

```cpp
#define TCPREPLAY_STATIC
#include <tcpreplay/tcpreplay_api.h>
#include <iostream>

int main() {
    tcpreplay_context* replay = tcpreplay_create();
    if (!replay) return 1;

    int result = tcpreplay_add_pcap(replay, "capture.pcap");
    result |= tcpreplay_set_output_pcap(replay, "resultat.pcap");
    result |= tcpreplay_set_speed(replay, TCPREPLAY_SPEED_TOP, 0.0);
    if (result == 0) result = tcpreplay_run(replay);

    if (result != 0)
        std::cerr << tcpreplay_last_error(replay) << '\n';

    tcpreplay_stats stats{};
    tcpreplay_get_stats(replay, &stats);
    std::cout << stats.packets << " paquets, " << stats.bytes << " octets\n";
    tcpreplay_destroy(replay);
    return result == 0 ? 0 : 1;
}
```

## C++ avec la DLL

Ne pas définir `TCPREPLAY_STATIC`. Ajouter `dist/include` aux includes, lier
`dist/lib/libtcpreplay.lib` et placer `libtcpreplay.dll` à côté de
l’exécutable ou dans un répertoire du `PATH`.

```cmake
add_executable(mon_replay main.cpp)
target_include_directories(mon_replay PRIVATE "C:/tcpreplay/dist/include")
target_link_libraries(mon_replay PRIVATE
    "C:/tcpreplay/dist/lib/libtcpreplay.lib")
```

## Injection sur une interface

Remplacer la sortie PCAP par le nom Npcap de la carte :

```cpp
tcpreplay_set_interface(replay,
    "\\\\Device\\NPF_{IDENTIFIANT-DE-LA-CARTE}");
tcpreplay_set_speed(replay, TCPREPLAY_SPEED_PPS, 1000.0);
```

Le nom exact s’obtient avec `tcpreplay.exe --listnics`.

## Python avec ctypes

Python doit avoir la même architecture que la DLL, ici x64. Copier
`libtcpreplay.dll` à côté de `libtcpreplay.py`, puis lancer :

```powershell
python libtcpreplay.py resultat.pcap capture.pcap
```

Pour une injection réseau :

```powershell
python libtcpreplay.py "\Device\NPF_{IDENTIFIANT}" capture.pcap
```

L’exemple définit les `argtypes`, `restype` et la structure de statistiques.
Il conserve le contexte comme `ctypes.c_void_p` et appelle toujours
`tcpreplay_destroy()` dans un bloc `finally`.

## Exécution asynchrone et arrêt

`tcpreplay_run()` est synchrone. Pour ne pas bloquer l’application, l’appeler
dans un thread de travail. Un autre thread peut demander l’arrêt avec
`tcpreplay_stop()` et consulter `tcpreplay_get_stats()` pendant le rejeu.

Ne pas modifier la configuration ni détruire le contexte tant que
`tcpreplay_run()` n’est pas terminé.

## Modes de vitesse

| Mode | Valeur |
| --- | --- |
| `TCPREPLAY_SPEED_CAPTURE` | rythme original ; valeur positive, généralement `1.0` |
| `TCPREPLAY_SPEED_TOP` | vitesse maximale ; valeur ignorée |
| `TCPREPLAY_SPEED_PPS` | paquets par seconde |
| `TCPREPLAY_SPEED_MBPS` | mégabits par seconde |
| `TCPREPLAY_SPEED_MULTIPLIER` | multiplicateur du rythme original |

Les timers sont `TCPREPLAY_TIMER_HYBRID`, `SELECT`, `GTOD`, `NANO` et
`IOPORT`. Le mode hybride est utilisé par défaut.

## Référence rapide

| Fonction | Rôle |
| --- | --- |
| `tcpreplay_create` / `tcpreplay_destroy` | crée et libère un contexte |
| `tcpreplay_add_pcap` | ajoute une capture |
| `tcpreplay_set_interface` | sélectionne une sortie Npcap |
| `tcpreplay_set_output_pcap` | sélectionne un PCAP de sortie |
| `tcpreplay_set_speed` / `tcpreplay_set_timer` | règle la cadence |
| `tcpreplay_set_loop` | règle les boucles, `0` signifiant infini |
| `tcpreplay_set_limit` | limite les paquets, `0` désactivant la limite |
| `tcpreplay_set_duration` | limite la durée, `0` désactivant la limite |
| `tcpreplay_run` / `tcpreplay_stop` | lance ou arrête le rejeu |
| `tcpreplay_get_stats` | copie les statistiques courantes |
| `tcpreplay_last_error` | retourne le dernier message d’erreur |

Les setters et `tcpreplay_run()` retournent `0` en cas de succès et `-1` en
cas d’échec. Le texte de `tcpreplay_last_error()` appartient au contexte et
reste valide jusqu’au prochain changement d’erreur ou à sa destruction.

## Licence

Le projet est distribué sous GPLv3. Une application redistribuée qui lie ou
embarque la bibliothèque doit respecter les obligations de cette licence.
