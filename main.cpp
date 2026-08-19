#define NOMINMAX
#include <pcap.h>
#include <windows.h>
#include <ws2tcpip.h>
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
std::atomic_bool stopped{false};
enum class Speed { Timed, Top, Pps, Mbps, Multiplier };
enum class TimerMode { Hybrid, Select, Gtod, Nano, Ioport };
struct Config {
    std::string input, iface;
    std::string srcIp, dstIp;
    int ifaceIndex = -1;
    int sourcePort = -1, destinationPort = -1;
    bool preload = false, verbose = false, showDelta = false, quiet = false;
    bool oneAtATime = false, suppressWarnings = false, printPid = false, statsEnabled = false;
    Speed speed = Speed::Timed;
    TimerMode timer = TimerMode::Hybrid;
    double rate = 1.0, duration = 0.0;
    double lossPercent = 0.0;
    uint64_t loops = 1, limit = 0, loopDelayNs = 0, maxSleepMs = 0;
    uint64_t ppsMulti = 1, statsInterval = 0;
};
struct Packet { std::vector<unsigned char> bytes; timeval ts{}; };
struct Stats { uint64_t packets=0, bytes=0, failed=0, dropped=0, processed=0; std::chrono::steady_clock::time_point start; };

void version() { std::cout << "tcpreplay version " << VERSION << " (Windows native, Npcap)\n"; }
void help() {
    version();
    std::cout <<
        "Usage: tcpreplay.exe [options] <capture.pcap>\n\n"
        "Interface:\n  -i, --intf1 <name|index>  interface Npcap de sortie\n"
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
        if (a=="--iface-index") { auto v=next(); uint64_t n; if(!v)return Parse::Error; if(!uintValue(v,n)||n>INT_MAX){error="index invalide";return Parse::Error;} c.ifaceIndex=(int)n; continue; }
        if (a=="-l" || a=="--loop") { auto v=next(); if(!v)return Parse::Error; if(!uintValue(v,c.loops)){error="boucles invalides";return Parse::Error;} continue; }
        if (a=="--duration") { auto v=next(); if(!v)return Parse::Error; if(!doubleValue(v,c.duration)){error="duree invalide";return Parse::Error;} continue; }
        if (a=="-L" || a=="--limit" || a=="--maxsleep" || a=="--loopdelay-ms" || a=="--loopdelay-ns" || a=="--pps-multi" || a=="--stats") {
            auto v=next();uint64_t n=0;if(!v)return Parse::Error;if(!uintValue(v,n)){error="valeur numerique invalide pour "+a;return Parse::Error;}
            if((a=="-L"||a=="--limit")&&n==0){error="--limit doit etre superieur a zero";return Parse::Error;}
            if(a=="-L"||a=="--limit")c.limit=n;else if(a=="--maxsleep")c.maxSleepMs=n;else if(a=="--loopdelay-ms"){if(n>UINT64_MAX/1000000ULL){error="delai de boucle trop grand";return Parse::Error;}c.loopDelayNs=n*1000000ULL;}else if(a=="--loopdelay-ns")c.loopDelayNs=n;else if(a=="--pps-multi"){if(n==0){error="--pps-multi doit etre superieur a zero";return Parse::Error;}c.ppsMulti=n;}else {c.statsInterval=n;c.statsEnabled=true;}continue;
        }
        if (a=="--loss") { auto v=next();if(!v)return Parse::Error;char* e=nullptr;errno=0;c.lossPercent=std::strtod(v,&e);if(errno||!e||*e||!std::isfinite(c.lossPercent)||c.lossPercent<0||c.lossPercent>100){error="--loss doit etre compris entre 0 et 100";return Parse::Error;}continue; }
        if (a=="--src-ip" || a=="--dst-ip") {
            auto v=next(); if(!v)return Parse::Error; in_addr address{};
            if(inet_pton(AF_INET,v,&address)!=1){error="adresse IPv4 invalide: "+std::string(v);return Parse::Error;}
            if(a=="--src-ip")c.srcIp=v;else c.dstIp=v; continue;
        }
        if (a=="--sport" || a=="--dport") {
            auto v=next(); uint64_t port=0; if(!v)return Parse::Error;
            if(!uintValue(v,port)||port==0||port>65535){error="port invalide: "+std::string(v);return Parse::Error;}
            if(a=="--sport")c.sourcePort=(int)port;else c.destinationPort=(int)port; continue;
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
        if (!c.input.empty()) { error="plusieurs fichiers d'entree"; return Parse::Error; }
        c.input=a;
    }
    if(c.input.empty()){error="fichier d'entree manquant";return Parse::Error;}
    if(c.iface.empty()&&c.ifaceIndex<0){error="interface manquante (-i/--intf1)";return Parse::Error;}
    if(c.ppsMulti!=1&&c.speed!=Speed::Pps){error="--pps-multi exige --pps";return Parse::Error;}
    if(c.quiet&&(c.verbose||c.showDelta)){error="--quiet est incompatible avec --verbose et --show-delta";return Parse::Error;}
    return Parse::Run;
}
bool interfaces(std::vector<std::string>& names, bool display) {
    pcap_if_t* all=nullptr; char error[PCAP_ERRBUF_SIZE]{};
    if(pcap_findalldevs(&all,error)==-1){std::cerr<<"Erreur Npcap: "<<error<<"\n";return false;}
    int i=0; for(auto d=all;d;d=d->next){names.emplace_back(d->name?d->name:"");if(display){std::cout<<i<<". "<<names.back();if(d->description)std::cout<<" ("<<d->description<<")";std::cout<<"\n";}++i;}
    pcap_freealldevs(all); return true;
}
bool load(const std::string& name, std::vector<Packet>& packets, std::string& error) {
    char err[PCAP_ERRBUF_SIZE]{}; auto file=pcap_open_offline(name.c_str(),err);
    if(!file){error=err;return false;} pcap_pkthdr* h=nullptr; const u_char* b=nullptr; int r;
    while((r=pcap_next_ex(file,&h,&b))==1) if(h->caplen) packets.push_back({{b,b+h->caplen},h->ts});
    if(r==-1)error=pcap_geterr(file); pcap_close(file); return r!=-1;
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
    double original=previous?delta(p.ts,previous->ts)/1000000.0:0; return c.speed==Speed::Multiplier?original/c.rate:original;
}
uint16_t read16(const unsigned char* p){return uint16_t(p[0])<<8|p[1];}
void write16(unsigned char* p,uint16_t value){p[0]=static_cast<unsigned char>(value>>8);p[1]=static_cast<unsigned char>(value);}
uint32_t checksumAdd(uint32_t sum,const unsigned char* data,size_t length){
    while(length>1){sum+=read16(data);data+=2;length-=2;}if(length)sum+=uint16_t(data[0])<<8;return sum;
}
uint16_t checksumFinish(uint32_t sum){while(sum>>16)sum=(sum&0xffff)+(sum>>16);return static_cast<uint16_t>(~sum);}
void rewrite(Packet& packet,const Config& c){
    auto& b=packet.bytes;if(b.size()<14)return;size_t ipOffset=14;uint16_t etherType=read16(b.data()+12);
    while((etherType==0x8100||etherType==0x88a8)&&b.size()>=ipOffset+4){etherType=read16(b.data()+ipOffset+2);ipOffset+=4;}
    if(etherType!=0x0800||b.size()<ipOffset+20)return;unsigned char* ip=b.data()+ipOffset;
    size_t ihl=(ip[0]&0x0f)*4;if((ip[0]>>4)!=4||ihl<20||b.size()<ipOffset+ihl)return;
    uint16_t totalLength=read16(ip+2);if(totalLength<ihl)return;
    bool requested=!c.srcIp.empty()||!c.dstIp.empty()||c.sourcePort>=0||c.destinationPort>=0;
    uint16_t fragment=read16(ip+6);if(requested&&((fragment&0x3fff)!=0||b.size()<ipOffset+totalLength))return;
    if(!c.srcIp.empty())inet_pton(AF_INET,c.srcIp.c_str(),ip+12);
    if(!c.dstIp.empty())inet_pton(AF_INET,c.dstIp.c_str(),ip+16);
    write16(ip+10,0);write16(ip+10,checksumFinish(checksumAdd(0,ip,ihl)));
    if(c.sourcePort<0&&c.destinationPort<0&&c.srcIp.empty()&&c.dstIp.empty())return;
    unsigned char protocol=ip[9];if(protocol!=IPPROTO_TCP&&protocol!=IPPROTO_UDP)return;
    size_t transportLength=totalLength-ihl;unsigned char* transport=ip+ihl;
    if((protocol==IPPROTO_TCP&&transportLength<20)||(protocol==IPPROTO_UDP&&transportLength<8))return;
    if(c.sourcePort>=0)write16(transport,static_cast<uint16_t>(c.sourcePort));
    if(c.destinationPort>=0)write16(transport+2,static_cast<uint16_t>(c.destinationPort));
    size_t checksumOffset=protocol==IPPROTO_TCP?16:6;write16(transport+checksumOffset,0);
    uint32_t sum=0;sum=checksumAdd(sum,ip+12,8);sum+=protocol;sum+=static_cast<uint16_t>(transportLength);sum=checksumAdd(sum,transport,transportLength);
    uint16_t result=checksumFinish(sum);if(protocol==IPPROTO_UDP&&result==0)result=0xffff;write16(transport+checksumOffset,result);
}
bool replay(const std::vector<Packet>& packets,pcap_t* dev,const Config& c,Stats& s){
    auto deadline=c.duration>0?s.start+std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::duration<double>(c.duration)):std::chrono::steady_clock::time_point::max();
    auto target=std::chrono::steady_clock::now(),nextStats=c.statsEnabled&&c.statsInterval>0?target+std::chrono::seconds(c.statsInterval):std::chrono::steady_clock::time_point::max();
    auto lastSend=std::chrono::steady_clock::now();bool firstSend=true;
    std::mt19937_64 random(static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));std::uniform_real_distribution<double> chance(0.0,100.0);
    for(uint64_t loop=0;(c.loops==0||loop<c.loops)&&!stopped;++loop){const Packet* previous=nullptr;
        for(const auto& original:packets){if(c.limit&&s.processed>=c.limit)return true;if(stopped||std::chrono::steady_clock::now()>=deadline)return true;double seconds=delay(c,original,previous);if(c.speed==Speed::Pps&&c.ppsMulti>1)seconds=(s.processed%c.ppsMulti==0)?double(c.ppsMulti)/c.rate:0.0;if(c.maxSleepMs)seconds=std::min(seconds,c.maxSleepMs/1000.0);target+=std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::duration<double>(seconds));waitUntil(std::min(target,deadline),c.timer);if(stopped||std::chrono::steady_clock::now()>=deadline)return true;
            ++s.processed;if(c.lossPercent>0&&chance(random)<c.lossPercent){++s.dropped;previous=&original;continue;}if(c.oneAtATime){std::cout<<"Appuyez sur Entree pour envoyer le paquet "<<s.processed<<"..."<<std::flush;std::string line;std::getline(std::cin,line);}
            Packet p=original;rewrite(p,c);auto now=std::chrono::steady_clock::now();if(c.showDelta&&!firstSend)std::cout<<"Delta: "<<std::chrono::duration_cast<std::chrono::microseconds>(now-lastSend).count()<<" us\n";lastSend=now;firstSend=false;
            if(pcap_sendpacket(dev,p.bytes.data(),(int)p.bytes.size())){++s.failed;std::cerr<<"Echec d'injection: "<<pcap_geterr(dev)<<"\n";return false;}++s.packets;s.bytes+=p.bytes.size();if(c.verbose)std::cout<<"packet "<<s.packets<<": "<<p.bytes.size()<<" octets\n";previous=&original;
            if(c.statsEnabled&&c.statsInterval>0&&now>=nextStats){double elapsed=std::chrono::duration<double>(now-s.start).count();std::cout<<"Progress: "<<s.packets<<" packets, "<<std::fixed<<std::setprecision(2)<<s.packets/std::max(elapsed,.000001)<<" pps\n";nextStats=now+std::chrono::seconds(c.statsInterval);}}
        if(c.statsEnabled&&c.statsInterval==0)std::cout<<"Loop "<<(loop+1)<<": "<<s.packets<<" packets sent\n";
        if(c.loopDelayNs&&(c.loops==0||loop+1<c.loops)){target=std::chrono::steady_clock::now()+std::chrono::nanoseconds(c.loopDelayNs);waitUntil(target,c.timer);}
    }
    return true;
}
BOOL WINAPI control(DWORD type){if(type==CTRL_C_EVENT||type==CTRL_BREAK_EVENT||type==CTRL_CLOSE_EVENT){stopped=true;return TRUE;}return FALSE;}
void stats(const Stats& s){double elapsed=std::chrono::duration<double>(std::chrono::steady_clock::now()-s.start).count(),safe=std::max(elapsed,.000001);std::cout<<std::fixed<<std::setprecision(2)<<"Actual: "<<s.packets<<" packets ("<<s.bytes<<" bytes) sent in "<<elapsed<<" seconds\nRated: "<<s.packets/safe<<" pps, "<<s.bytes*8.0/safe/1000000.0<<" Mbps\nFailed write attempts: "<<s.failed<<"\nPackets dropped by --loss: "<<s.dropped<<"\n";}
}
int main(int argc,char** argv){
    Config c;std::string error;auto parsed=parse(argc,argv,c,error);if(parsed==Parse::Exit)return 0;if(parsed==Parse::Error){std::cerr<<"Erreur: "<<error<<"\nUtilisez --help pour l'aide.\n";return 1;}
    std::vector<std::string> nics;if(!interfaces(nics,parsed==Parse::List))return 1;if(parsed==Parse::List)return 0;
    if(c.ifaceIndex>=0){if((size_t)c.ifaceIndex>=nics.size()){std::cerr<<"Erreur: index hors limites\n";return 1;}c.iface=nics[c.ifaceIndex];}else{uint64_t i;if(uintValue(c.iface,i)){if(i>=nics.size()){std::cerr<<"Erreur: index hors limites\n";return 1;}c.iface=nics[(size_t)i];}}
    if(c.printPid&&!c.quiet)std::cout<<"PID: "<<GetCurrentProcessId()<<"\n";
    std::vector<Packet> packets;if(!load(c.input,packets,error)){std::cerr<<"Erreur de lecture: "<<error<<"\n";return 1;}if(packets.empty()){std::cerr<<"Erreur: capture vide\n";return 1;}if(c.preload&&!c.quiet)std::cout<<"Preloaded "<<packets.size()<<" packets into memory\n";
    char err[PCAP_ERRBUF_SIZE]{};auto dev=pcap_open_live(c.iface.c_str(),65535,0,1,err);if(!dev){std::cerr<<"Erreur d'ouverture: "<<err<<"\n";return 1;}SetConsoleCtrlHandler(control,TRUE);Stats s;s.start=std::chrono::steady_clock::now();bool ok=replay(packets,dev,c,s);stats(s);pcap_close(dev);return ok?0:1;
}
