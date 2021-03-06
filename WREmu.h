/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   WREmu.h
 * Author: jens
 *
 * Created on 3. April 2017, 15:35
 */

#ifndef WREMU_H
#define WREMU_H

#ifdef __cplusplus
extern "C" {
#endif

// Header-Files

/* Max. Anzahl Wechselrichter (MAXWR)
   256   (Klasse C-Netzwerk)
   65536 (Klasse B-Netzwerk)
   16777216 (Klasse A-Netzwerk)
 */
#define MAXWR 65535

/* MAC-Adresse fuer Pseudo-WR 
   Klasse C => 0xcc
   Klasse B => 0xbb 0xcc
   Klasse A => 0xaa 0xbb 0xcc
 */
const unsigned char MACMUSTER[] = {0x90,0x80,0x12,0xAA,0xBB,0xCC};

/* IP-Adressen Bereiche
   Klasse C => 192.168.[1-254].0
   Klasse B => 172.[16-31].0.0
   Klasse A => 10.0.0.0
 */
const unsigned char IPMUSTER[]  = {172,16,0,0};

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

#ifdef __cplusplus
}
#endif

#endif /* WREMU_H */

