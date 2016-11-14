// Header-Files

/* Max. Anzahl Wechselrichter (MAXWR)
   256   (Klasse C-Netzwerk)
   65536 (Klasse B-Netzwerk)
   16777216 (Klasse A-Netzwerk)
 */
#define MAXWR 65535

/* MAC-Adresse fuer Pseudo-WR */
const unsigned char MACMUSTER[] = {0x90,0x80,0x12,0xAA,0xBB,0xCC};

/* IP-Adressen Bereiche
   Klasse C => 192.168.254.1
   Klasse B => 172.31.0.1
   Klasse A => 10.0.0.0
 */
const unsigned char IPMUSTER[]  = {172,16,0,1};

//Struktur eines WR
struct WR
{
    int	pos;
    int SetpointP;
    int SetpointQ;
    int SetpointCosPhi;
    int Akt_Pac;
    int Akt_Qac;
    int Akt_Uac;
    int Akt_Udc;
    int Akt_fac;
    int Akt_CosPhi;
    int Aktiv;
    int Fehler;
    int Delay;
    int Jitter;
    int Random;
    int TCP_SYN;
    int TCP_FIN;
    int TCP_Con;
};  


