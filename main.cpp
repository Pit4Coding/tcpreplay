#define NOMINMAX
#include <pcap.h>
#include <windows.h>
#include <ws2tcpip.h>
#include "packet_edit.h"
#include "pcap_source.h"
#include "tcpprep_cache.h"
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
#include <string>
#include <thread>
#include <vector>

namespace {
#pragma comment(lib, "ws2_32.lib")
constexpr const char* VERSION = "4.6.0-win.1";
std::string programName = "tcpreplay";
std::atomic_bool stopped{false};
enum class Speed { Timed, Top, Pps, Mbps, Multiplier };
enum class TimerMode { Hybrid, Select, Gtod, Nano, Ioport };
struct PacketRange { uint64_t first=0,last=0; };
struct Config {
    std::vector<std::string> inputs;
    std::string iface, iface2;
    std::string cacheFile;
    std::string outputFile;
    RewriteOptions rewriteOptions;
    int ifaceIndex = -1;
    bool preload = false, verbose = false, showDelta = false, quiet = false;
    bool oneAtATime = false, suppressWarnings = false, printPid = false, statsEnabled = false, dualFile = false;
    Speed speed = Speed::Timed;
    TimerMode timer = TimerMode::Hybrid;
    double rate = 1.0, duration = 0.0;
    double lossPercent = 0.0;
    uint64_t loops = 1, limit = 0, loopDelayNs = 0, maxSleepMs = 0;
    uint64_t ppsMulti = 1, statsInterval = 0;
    std::vector<PacketRange> selection;
    bool includeSelection = false, excludeSelection = false;
    TcpprepCache cache;
};
struct Stats { uint64_t packets=0, bytes=0, failed=0, dropped=0, processed=0; std::chrono::steady_clock::time_point start; };

void version() { std::cout << programName << " version " << VERSION << " (Windows native, Npcap)\n"; }
void help() {
    version();
    std::cout <<
        "Usage: " << programName << ".exe [options] <capture1.pcap> [capture2.pcap ...]\n\n"
        "Interface:\n  -i, --intf1 <name|index>  interface Npcap de sortie\n"
        "  -I, --intf2 <name|index>  seconde interface de sortie\n"
        "  -2, --dualfile           fusionne deux captures directionnelles\n"
        "  -c, --cachefile <fichier> repartit via un cache tcpprep v04\n"
        "  -w, --write <fichier>    ecrit les paquets dans un PCAP\n"
        "      --listnics           liste les interfaces\n\n"
        "Vitesse (mutuellement exclusive):\n"
        "  -t, --topspeed           vitesse maximale\n"
        "  -p, --pps <n>            paquets par seconde\n"
        "  -M, --mbps <n>           debit en Mbit/s\n"
        "  -x, --multiplier <n>     multiplicateur temporel\n\n"
        "Controle:\n  -l, --loop <n>           repetitions (0 = infini)\n"
        "      --duration <sec>     duree maximale\n"
        "  -L, --limit <n>          nombre maximal de paquets\n"
        "  -T, --timer <mode>       select, gtod, nano ou ioport\n"
        "      --maxsleep <ms>      plafonne l'attente entre paquets\n"
        "      --loopdelay-ms <ms>  attente entre les boucles\n"
        "      --loopdelay-ns <ns>  attente nanoseconde entre boucles\n"
        "  -o, --oneatatime         attend une entree avant chaque paquet\n"
        "      --pps-multi <n>      paquets par intervalle PPS\n"
        "      --loss <pct>         pertes aleatoires de 0 a 100 %\n"
        "  -q, --quiet              statistiques finales uniquement\n"
        "  -P, --pid                affiche le PID au demarrage\n"
        "      --stats <sec>        statistiques periodiques\n"
        "  -W, --suppress-warnings  masque les avertissements\n"
        "      --include <liste>    envoie seulement les numeros selectionnes\n"
        "      --exclude <liste>    exclut les numeros selectionnes\n"
        "  -K, --preload-pcap       prechargement en memoire\n"
        "      --src-ip <adresse>   reecrit l'adresse IPv4 source\n"
        "      --dst-ip <adresse>   reecrit l'adresse IPv4 destination\n"
        "      --sport <port>       reecrit le port TCP/UDP source\n"
        "      --dport <port>       reecrit le port TCP/UDP destination\n"
        "      --show-delta         affiche le delai reel entre envois\n"
        "  -v, --verbose            detail des envois\n"
        "  -V, --version            version\n  -h, --help               aide\n\n"
        "Alias historiques acceptes: --iface, --iface-index, --preload, --show-interfaces.\n";
}
bool uintValue(const std::string& s, uint64_t& out) {
    if (s.empty() || s[0]=='-') return false;
    char* e=nullptr; errno=0; auto v=std::strtoull(s.c_str(), &e, 10);
    if (errno || !e || *e) return false; out=static_cast<uint64_t>(v); return true;
}
bool doubleValue(const std::string& s, double& out) {
    char* e=nullptr; errno=0; out=std::strtod(s.c_str(), &e);
    return !errno && e && !*e && std::isfinite(out) && out>0;
}
bool speed(Config& c, Speed s, double rate, std::string& error) {
    if (c.speed != Speed::Timed) { error="une seule option de vitesse est permise"; return false; }
    c.speed=s; c.rate=rate; return true;
}
bool parseSelection(std::string text,std::vector<PacketRange>& ranges){
    if(text.rfind("P:",0)==0||text.rfind("p:",0)==0)text=text.substr(2);if(text.empty())return false;
    size_t begin=0;while(begin<text.size()){size_t comma=text.find(',',begin);std::string part=text.substr(begin,comma==std::string::npos?std::string::npos:comma-begin);if(part.empty())return false;size_t dash=part.find('-');uint64_t first=0,last=0;
        if(dash==std::string::npos){if(!uintValue(part,first)||first==0)return false;last=first;}else{std::string left=part.substr(0,dash),right=part.substr(dash+1);if(!uintValue(left,first)||first==0)return false;if(right.empty())last=UINT64_MAX;else if(!uintValue(right,last)||last<first)return false;}
        ranges.push_back({first,last});if(comma==std::string::npos)break;begin=comma+1;}
    return true;
}
bool selected(const Config& c,uint64_t number){bool match=false;for(const auto& range:c.selection)if(number>=range.first&&number<=range.last){match=true;break;}return c.includeSelection?match:c.excludeSelection?!match:true;}
enum class Parse { Run, Exit, List, Error };
Parse parse(int argc, char** argv, Config& c, std::string& error) {
    for (int i=1; i<argc; ++i) {
        std::string a=argv[i];
        auto next=[&]() -> const char* { if (++i>=argc) { error="valeur manquante pour "+a; return nullptr; } return argv[i]; };
        if (a=="-h" || a=="--help") { help(); return Parse::Exit; }
        if (a=="-V" || a=="--version") { version(); return Parse::Exit; }
        if (a=="--listnics" || a=="--show-interfaces") return Parse::List;
        if (a=="-v" || a=="--verbose" || a=="--log") { c.verbose=true; continue; }
        if (a=="--show-delta") { c.showDelta=true; continue; }
        if (a=="-q" || a=="--quiet") { c.quiet=true; continue; }
        if (a=="-P" || a=="--pid") { c.printPid=true; continue; }
        if (a=="-W" || a=="--suppress-warnings") { c.suppressWarnings=true; continue; }
        if (a=="-o" || a=="--oneatatime") { if(!speed(c,Speed::Top,0,error))return Parse::Error;c.oneAtATime=true;continue; }
        if (a=="-K" || a=="--preload-pcap" || a=="--preload") { c.preload=true; continue; }
        if (a=="-t" || a=="--topspeed") { if (!speed(c,Speed::Top,0,error)) return Parse::Error; continue; }
        if (a=="-i" || a=="--intf1" || a=="--iface") { auto v=next(); if(!v)return Parse::Error; c.iface=v; continue; }
        if (a=="-I" || a=="--intf2") { auto v=next(); if(!v)return Parse::Error; c.iface2=v; continue; }
        if (a=="-2" || a=="--dualfile") { c.dualFile=true; continue; }
        if (a=="-c" || a=="--cachefile") { auto v=next();if(!v)return Parse::Error;c.cacheFile=v;continue; }
        if (a=="-w" || a=="--write") { auto v=next();if(!v)return Parse::Error;c.outputFile=v;continue; }
        if (a=="--iface-index") { auto v=next(); uint64_t n; if(!v)return Parse::Error; if(!uintValue(v,n)||n>INT_MAX){error="index invalide";return Parse::Error;} c.ifaceIndex=(int)n; continue; }
        if (a=="-l" || a=="--loop") { auto v=next(); if(!v)return Parse::Error; if(!uintValue(v,c.loops)){error="boucles invalides";return Parse::Error;} continue; }
        if (a=="--duration") { auto v=next(); if(!v)return Parse::Error; if(!doubleValue(v,c.duration)){error="duree invalide";return Parse::Error;} continue; }
        if (a=="-L" || a=="--limit" || a=="--maxsleep" || a=="--loopdelay-ms" || a=="--loopdelay-ns" || a=="--pps-multi" || a=="--stats") {
            auto v=next();uint64_t n=0;if(!v)return Parse::Error;if(!uintValue(v,n)){error="valeur numerique invalide pour "+a;return Parse::Error;}
            if((a=="-L"||a=="--limit")&&n==0){error="--limit doit etre superieur a zero";return Parse::Error;}
            if(a=="-L"||a=="--limit")c.limit=n;else if(a=="--maxsleep")c.maxSleepMs=n;else if(a=="--loopdelay-ms"){if(n>UINT64_MAX/1000000ULL){error="delai de boucle trop grand";return Parse::Error;}c.loopDelayNs=n*1000000ULL;}else if(a=="--loopdelay-ns")c.loopDelayNs=n;else if(a=="--pps-multi"){if(n==0){error="--pps-multi doit etre superieur a zero";return Parse::Error;}c.ppsMulti=n;}else {c.statsInterval=n;c.statsEnabled=true;}continue;
        }
        if (a=="--loss") { auto v=next();if(!v)return Parse::Error;char* e=nullptr;errno=0;c.lossPercent=std::strtod(v,&e);if(errno||!e||*e||!std::isfinite(c.lossPercent)||c.lossPercent<0||c.lossPercent>100){error="--loss doit etre compris entre 0 et 100";return Parse::Error;}continue; }
        if (a=="--include" || a=="--exclude") { auto v=next();if(!v)return Parse::Error;if(c.includeSelection||c.excludeSelection){error="--include et --exclude sont mutuellement exclusifs";return Parse::Error;}if(!parseSelection(v,c.selection)){error="selection de paquets invalide: "+std::string(v);return Parse::Error;}c.includeSelection=a=="--include";c.excludeSelection=a=="--exclude";continue; }
        if (a=="--src-ip" || a=="--dst-ip") {
            auto v=next(); if(!v)return Parse::Error; in_addr address{};
            if(inet_pton(AF_INET,v,&address)!=1){error="adresse IPv4 invalide: "+std::string(v);return Parse::Error;}
            if(a=="--src-ip")c.rewriteOptions.sourceIp=v;else c.rewriteOptions.destinationIp=v; continue;
        }
        if (a=="--sport" || a=="--dport") {
            auto v=next(); uint64_t port=0; if(!v)return Parse::Error;
            if(!uintValue(v,port)||port==0||port>65535){error="port invalide: "+std::string(v);return Parse::Error;}
            if(a=="--sport")c.rewriteOptions.sourcePort=(int)port;else c.rewriteOptions.destinationPort=(int)port; continue;
        }
        if (a=="-T" || a=="--timer") {
            auto v=next(); if(!v)return Parse::Error; std::string mode=v;
            if(mode=="select")c.timer=TimerMode::Select;
            else if(mode=="gtod")c.timer=TimerMode::Gtod;
            else if(mode=="nano")c.timer=TimerMode::Nano;
            else if(mode=="ioport")c.timer=TimerMode::Ioport;
            else { error="mode de temporisation invalide: "+mode; return Parse::Error; }
            continue;
        }
        if (a=="-p" || a=="--pps" || a=="-M" || a=="--mbps" || a=="-x" || a=="--multiplier") {
            auto v=next(); double n; if(!v)return Parse::Error; if(!doubleValue(v,n)){error="vitesse invalide";return Parse::Error;}
            Speed mode=(a=="-p"||a=="--pps")?Speed::Pps:(a=="-M"||a=="--mbps")?Speed::Mbps:Speed::Multiplier;
            if(!speed(c,mode,n,error))return Parse::Error; continue;
        }
        if (!a.empty() && a[0]=='-') { error="option inconnue: "+a; return Parse::Error; }
        c.inputs.push_back(a);
    }
    if(c.inputs.empty()){error="fichier d'entree manquant";return Parse::Error;}
    if(c.outputFile.empty()&&c.iface.empty()&&c.ifaceIndex<0){error="interface manquante (-i/--intf1)";return Parse::Error;}
    if(c.ppsMulti!=1&&c.speed!=Speed::Pps){error="--pps-multi exige --pps";return Parse::Error;}
    if(c.quiet&&(c.verbose||c.showDelta)){error="--quiet est incompatible avec --verbose et --show-delta";return Parse::Error;}
    if(c.dualFile&&(c.inputs.size()!=2||c.iface2.empty())){error="--dualfile exige exactement deux captures et --intf2";return Parse::Error;}
    if(!c.cacheFile.empty()&&(c.iface2.empty()||c.inputs.size()!=1||c.dualFile)){error="--cachefile exige une capture, --intf2 et exclut --dualfile";return Parse::Error;}
    if(!c.outputFile.empty()&&(!c.iface2.empty()||!c.cacheFile.empty()||c.dualFile)){error="--write est incompatible avec --intf2, --cachefile et --dualfile";return Parse::Error;}
    return Parse::Run;
}
bool interfaces(std::vector<std::string>& names, bool display) {
    pcap_if_t* all=nullptr; char error[PCAP_ERRBUF_SIZE]{};
    if(pcap_findalldevs(&all,error)==-1){std::cerr<<"Erreur Npcap: "<<error<<"\n";return false;}
    int i=0; for(auto d=all;d;d=d->next){names.emplace_back(d->name?d->name:"");if(display){std::cout<<i<<". "<<names.back();if(d->description)std::cout<<" ("<<d->description<<")";std::cout<<"\n";}++i;}
    pcap_freealldevs(all); return true;
}
uint64_t delta(const timeval& a,const timeval& b){int64_t d=(int64_t(a.tv_sec)-b.tv_sec)*1000000LL+a.tv_usec-b.tv_usec;return d>0?(uint64_t)d:0;}
void waitUntil(std::chrono::steady_clock::time_point target,TimerMode mode){
    if(mode==TimerMode::Select){while(!stopped){auto now=std::chrono::steady_clock::now();if(now>=target)return;std::this_thread::sleep_for(std::min(target-now,std::chrono::steady_clock::duration(std::chrono::milliseconds(1))));}return;}
    if(mode==TimerMode::Gtod||mode==TimerMode::Ioport){while(!stopped&&std::chrono::steady_clock::now()<target){if(mode==TimerMode::Gtod)SwitchToThread();}return;}
    if(mode==TimerMode::Nano){LARGE_INTEGER frequency,now,start;QueryPerformanceFrequency(&frequency);QueryPerformanceCounter(&start);auto remaining=target-std::chrono::steady_clock::now();double seconds=std::chrono::duration<double>(remaining).count();do{QueryPerformanceCounter(&now);}while(!stopped&&double(now.QuadPart-start.QuadPart)/frequency.QuadPart<seconds);return;}
    while(!stopped){auto now=std::chrono::steady_clock::now();if(now>=target)return;auto left=target-now;if(left>std::chrono::milliseconds(2))std::this_thread::sleep_for(left-std::chrono::milliseconds(1));else SwitchToThread();}
}
double delay(const Config& c,const Packet& p,const Packet* previous){
    if(c.speed==Speed::Top)return 0; if(c.speed==Speed::Pps)return 1/c.rate;
    if(c.speed==Speed::Mbps)return p.bytes.size()*8.0/(c.rate*1000000.0);
    double original=previous?delta(p.timestamp,previous->timestamp)/1000000.0:0; return c.speed==Speed::Multiplier?original/c.rate:original;
}
bool replay(PacketSource& source,pcap_t* dev,pcap_t* dev2,pcap_dumper_t* dumper,const Config& c,Stats& s){
    auto deadline=c.duration>0?s.start+std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::duration<double>(c.duration)):std::chrono::steady_clock::time_point::max();
    auto target=std::chrono::steady_clock::now(),nextStats=c.statsEnabled&&c.statsInterval>0?target+std::chrono::seconds(c.statsInterval):std::chrono::steady_clock::time_point::max();
    auto lastSend=std::chrono::steady_clock::now();bool firstSend=true;
    std::mt19937_64 random(static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));std::uniform_real_distribution<double> chance(0.0,100.0);
    for(uint64_t loop=0;(c.loops==0||loop<c.loops)&&!stopped;++loop){Packet previous{};bool hasPrevious=false,hasPackets=false;uint64_t packetNumber=0;std::string sourceError;if(!source.reset(sourceError)){std::cerr<<sourceError<<"\n";return false;}
        while(true){Packet original;int read=source.next(original,sourceError);if(read<0){std::cerr<<sourceError<<"\n";return false;}if(read==0)break;hasPackets=true;++packetNumber;if(!c.cacheFile.empty()){if(packetNumber>c.cache.packetCount){std::cerr<<"Erreur: la capture contient plus de paquets que le cache tcpprep\n";return false;}int direction=tcpprepDirection(c.cache,packetNumber);if(direction<0)continue;original.output=direction;}if(!selected(c,packetNumber))continue;if(c.limit&&s.processed>=c.limit)return true;if(stopped||std::chrono::steady_clock::now()>=deadline)return true;double seconds=delay(c,original,hasPrevious?&previous:nullptr);if(c.speed==Speed::Pps&&c.ppsMulti>1)seconds=(s.processed%c.ppsMulti==0)?double(c.ppsMulti)/c.rate:0.0;if(c.maxSleepMs)seconds=std::min(seconds,c.maxSleepMs/1000.0);target+=std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::duration<double>(seconds));waitUntil(std::min(target,deadline),c.timer);if(stopped||std::chrono::steady_clock::now()>=deadline)return true;
            ++s.processed;if(c.lossPercent>0&&chance(random)<c.lossPercent){++s.dropped;previous.timestamp=original.timestamp;hasPrevious=true;continue;}if(c.oneAtATime){std::cout<<"Appuyez sur Entree pour envoyer le paquet "<<s.processed<<"..."<<std::flush;std::string line;std::getline(std::cin,line);}
            Packet p=original;rewritePacket(p.bytes,c.rewriteOptions);auto now=std::chrono::steady_clock::now();if(c.showDelta&&!firstSend)std::cout<<"Delta: "<<std::chrono::duration_cast<std::chrono::microseconds>(now-lastSend).count()<<" us\n";lastSend=now;firstSend=false;
            if(dumper){pcap_pkthdr header{};header.ts=p.timestamp;header.caplen=header.len=static_cast<bpf_u_int32>(p.bytes.size());pcap_dump(reinterpret_cast<u_char*>(dumper),&header,p.bytes.data());}else{pcap_t* output=p.output==1&&dev2?dev2:dev;if(pcap_sendpacket(output,p.bytes.data(),(int)p.bytes.size())){++s.failed;std::cerr<<"Echec d'injection: "<<pcap_geterr(output)<<"\n";return false;}}++s.packets;s.bytes+=p.bytes.size();if(c.verbose)std::cout<<"packet "<<s.packets<<(dumper?" -> pcap":" -> intf"+std::to_string(p.output+1))<<": "<<p.bytes.size()<<" octets\n";previous.timestamp=original.timestamp;hasPrevious=true;
            if(c.statsEnabled&&c.statsInterval>0&&now>=nextStats){double elapsed=std::chrono::duration<double>(now-s.start).count();std::cout<<"Progress: "<<s.packets<<" packets, "<<std::fixed<<std::setprecision(2)<<s.packets/std::max(elapsed,.000001)<<" pps\n";nextStats=now+std::chrono::seconds(c.statsInterval);}}
        if(!hasPackets){std::cerr<<"Erreur: les captures ne contiennent aucun paquet\n";return false;}if(!c.cacheFile.empty()&&packetNumber!=c.cache.packetCount){std::cerr<<"Erreur: le cache tcpprep contient "<<c.cache.packetCount<<" decisions pour "<<packetNumber<<" paquets\n";return false;}
        if(c.statsEnabled&&c.statsInterval==0)std::cout<<"Loop "<<(loop+1)<<": "<<s.packets<<" packets sent\n";
        if(c.loopDelayNs&&(c.loops==0||loop+1<c.loops)){target=std::chrono::steady_clock::now()+std::chrono::nanoseconds(c.loopDelayNs);waitUntil(target,c.timer);}
    }
    return true;
}
BOOL WINAPI control(DWORD type){if(type==CTRL_C_EVENT||type==CTRL_BREAK_EVENT||type==CTRL_CLOSE_EVENT){stopped=true;return TRUE;}return FALSE;}
void stats(const Stats& s){double elapsed=std::chrono::duration<double>(std::chrono::steady_clock::now()-s.start).count(),safe=std::max(elapsed,.000001);std::cout<<std::fixed<<std::setprecision(2)<<"Actual: "<<s.packets<<" packets ("<<s.bytes<<" bytes) sent in "<<elapsed<<" seconds\nRated: "<<s.packets/safe<<" pps, "<<s.bytes*8.0/safe/1000000.0<<" Mbps\nFailed write attempts: "<<s.failed<<"\nPackets dropped by --loss: "<<s.dropped<<"\n";}
}
int main(int argc,char** argv){
    if(argc>0&&argv[0]){programName=argv[0];size_t slash=programName.find_last_of("\\/");if(slash!=std::string::npos)programName=programName.substr(slash+1);if(programName.size()>4&&programName.substr(programName.size()-4)==".exe")programName.resize(programName.size()-4);}
    Config c;std::string error;auto parsed=parse(argc,argv,c,error);if(parsed==Parse::Exit)return 0;if(parsed==Parse::Error){std::cerr<<"Erreur: "<<error<<"\nUtilisez --help pour l'aide.\n";return 1;}
    std::vector<std::string> nics;if(parsed==Parse::List){if(!interfaces(nics,true))return 1;return 0;}if(c.outputFile.empty()){if(!interfaces(nics,false))return 1;if(c.ifaceIndex>=0){if((size_t)c.ifaceIndex>=nics.size()){std::cerr<<"Erreur: index hors limites\n";return 1;}c.iface=nics[c.ifaceIndex];}else{uint64_t i;if(uintValue(c.iface,i)){if(i>=nics.size()){std::cerr<<"Erreur: index hors limites\n";return 1;}c.iface=nics[(size_t)i];}}if(!c.iface2.empty()){uint64_t i;if(uintValue(c.iface2,i)){if(i>=nics.size()){std::cerr<<"Erreur: index de seconde interface hors limites\n";return 1;}c.iface2=nics[(size_t)i];}}}
    if(!c.cacheFile.empty()&&!loadTcpprepCache(c.cacheFile,c.cache,error)){std::cerr<<"Erreur: "<<error<<"\n";return 1;}
    if(c.printPid&&!c.quiet)std::cout<<"PID: "<<GetCurrentProcessId()<<"\n";
    std::vector<Packet> packets;if(c.preload){if(c.dualFile){if(!preloadPcap(c.inputs[0],packets,error,0)||!preloadPcap(c.inputs[1],packets,error,1)){std::cerr<<"Erreur de lecture: "<<error<<"\n";return 1;}std::stable_sort(packets.begin(),packets.end(),[](const Packet& a,const Packet& b){return a.timestamp.tv_sec<b.timestamp.tv_sec||(a.timestamp.tv_sec==b.timestamp.tv_sec&&a.timestamp.tv_usec<b.timestamp.tv_usec);});}else for(const auto& input:c.inputs)if(!preloadPcap(input,packets,error)){std::cerr<<"Erreur de lecture de "<<input<<": "<<error<<"\n";return 1;}if(packets.empty()){std::cerr<<"Erreur: capture vide\n";return 1;}if(!c.quiet)std::cout<<"Preloaded "<<packets.size()<<" packets into memory\n";}
    char err[PCAP_ERRBUF_SIZE]{};pcap_t* dev=nullptr;pcap_t* dev2=nullptr;pcap_t* dumpContext=nullptr;pcap_dumper_t* dumper=nullptr;
    if(!c.outputFile.empty()){dumpContext=pcap_open_offline(c.inputs[0].c_str(),err);if(!dumpContext){std::cerr<<"Erreur de lecture: "<<err<<"\n";return 1;}int dlt=pcap_datalink(dumpContext);for(size_t i=1;i<c.inputs.size();++i){pcap_t* check=pcap_open_offline(c.inputs[i].c_str(),err);if(!check){std::cerr<<"Erreur de lecture: "<<err<<"\n";pcap_close(dumpContext);return 1;}bool compatible=pcap_datalink(check)==dlt;pcap_close(check);if(!compatible){std::cerr<<"Erreur: les captures ont des types de liaison differents\n";pcap_close(dumpContext);return 1;}}dumper=pcap_dump_open(dumpContext,c.outputFile.c_str());if(!dumper){std::cerr<<"Erreur de creation du PCAP: "<<pcap_geterr(dumpContext)<<"\n";pcap_close(dumpContext);return 1;}}
    else{dev=pcap_open_live(c.iface.c_str(),65535,0,1,err);if(!dev){std::cerr<<"Erreur d'ouverture: "<<err<<"\n";return 1;}if(!c.iface2.empty()){dev2=pcap_open_live(c.iface2.c_str(),65535,0,1,err);if(!dev2){std::cerr<<"Erreur d'ouverture de la seconde interface: "<<err<<"\n";pcap_close(dev);return 1;}}}
    SetConsoleCtrlHandler(control,TRUE);Stats s;s.start=std::chrono::steady_clock::now();bool ok=false;if(c.preload){MemorySource source(packets);ok=replay(source,dev,dev2,dumper,c,s);}else if(c.dualFile){DualFileSource source(c.inputs);ok=replay(source,dev,dev2,dumper,c,s);}else{FileSource source(c.inputs);ok=replay(source,dev,dev2,dumper,c,s);}if(dumper&&pcap_dump_flush(dumper)!=0){std::cerr<<"Erreur de finalisation du PCAP\n";ok=false;}stats(s);if(dumper)pcap_dump_close(dumper);if(dumpContext)pcap_close(dumpContext);if(dev2)pcap_close(dev2);if(dev)pcap_close(dev);return ok?0:1;
}
