/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/file.h>
#include "WREmu.h"

// Analyse des Datenpaketes
// R�ckgabewerte, siehe Switch-Funktion in Main
int SelectPaket(const u_char *Packet,int length,struct WR Datenarray[MAXWR],pcap_t *info)
{
  int i;
  int result   = 0;
  unsigned int csum, csum1, csum2, csum3;
  unsigned char srcip1,srcip2,srcip3,srcip4,dstip1,dstip2,dstip3,dstip4;
  unsigned char srcmac1,srcmac2,srcmac3,srcmac4,srcmac5,srcmac6;
  unsigned char dstmac1,dstmac2,dstmac3,dstmac4,dstmac5,dstmac6;
  unsigned char txarray[1600];

  //IP-Datenpaket
  if((*(Packet+12) == 8) && (*(Packet+13) == 0))
  {
    //ICMP-Datenpaket
    if(*(Packet+23) == 1)
    {
      if(*(Packet+34) == 8) // PING-Request
      {
        txarray[30] = *(Packet+26); // Source IP 1
        txarray[31] = *(Packet+27); // Source IP 2
        txarray[32] = *(Packet+28); // Source IP 3
        txarray[33] = *(Packet+29); // Source IP 4
        txarray[26] = *(Packet+30); // Dest. IP 1
        txarray[27] = *(Packet+31); // Dest. IP 2
        txarray[28] = *(Packet+32); // Dest. IP 3
        txarray[29] = *(Packet+33); // Dest. IP 4
        txarray[6] = *(Packet+0);   // Source MAC 1
        txarray[7] = *(Packet+1);   // Source MAC 2
        txarray[8] = *(Packet+2);   // Source MAC 3
        txarray[9] = *(Packet+3);   // Source MAC 4
        txarray[10] = *(Packet+4);  // Source MAC 5
        txarray[11] = *(Packet+5);  // Source MAC 6
        txarray[0] = *(Packet+6);   // Dest. MAC 1
        txarray[1] = *(Packet+7);   // Dest. MAC 2
        txarray[2] = *(Packet+8);   // Dest. MAC 3
        txarray[3] = *(Packet+9);   // Dest. MAC 4
        txarray[4] = *(Packet+10);  // Dest. MAC 5
        txarray[5] = *(Packet+11);  // Dest. MAC 6
        txarray[38] = *(Packet+38); // Identifier
        txarray[39] = *(Packet+39); // Identifier
        txarray[40] = *(Packet+40); // Sequence Number
        txarray[41] = *(Packet+41); // Sequence Number
        
        txarray[12] = 0x08; // IP v4 Protokoll
        txarray[13] = 0x00;
        txarray[14] = 0x45; // Headerlength
        txarray[15] = 0x00; // Service
        txarray[16] = 0x00; // Total Length
        txarray[17] = 0x3c; 
        txarray[18] = *(Packet+18); // Identifikation
        txarray[19] = *(Packet+19);
        txarray[20] = 0x00; // Flags
        txarray[21] = 0x00;
        txarray[22] = 0x3a; // TTL
        txarray[23] = 0x01; // ICMP Protokoll
        txarray[24] = 0x00; // Header Checksum
        txarray[25] = 0x00;
        txarray[34] = 0x00; // Type Echo Replay
        txarray[35] = 0x00;
        txarray[36] = 0x00; // Checksum
        txarray[37] = 0x00; // Checksum
 
        csum = 0;
        for(i=14;i<34;i=i+2)
        {
          csum1 = txarray[i] & 0x000000ff;
          csum2 = txarray[i+1] & 0x000000ff;
          csum1 = csum1 << 8;
          csum3 = (csum1 & 0x0000ff00) | (csum2 & 0x000000ff);
          csum  = csum + csum3;
          if(csum > 0x0000ffff)
          {
            csum3 = csum & 0xffff0000;
            csum3 = csum3 >> 16;
            csum = csum & 0x0000ffff;
            csum = csum + (csum3 & 0x0000ffff);
          }
        }
        csum = ~csum;
        csum1 = csum & 0xff00;
        csum1 = csum1 >> 8;
        csum2 = csum & 0x00ff;

        txarray[24] = csum1 & 0x00ff; // Header Checksum
        txarray[25] = csum2 & 0x00ff;


        csum = 0;
        for(i=34;i<length;i=i+2)
        {
          csum1 = txarray[i] & 0x000000ff;
          csum2 = txarray[i+1] & 0x000000ff;
          csum1 = csum1 << 8;
          csum3 = (csum1 & 0x0000ff00) | (csum2 & 0x000000ff);
          csum  = csum + csum3;
          if(csum > 0x0000ffff)
          {
            csum3 = csum & 0xffff0000;
            csum3 = csum3 >> 16;
            csum = csum & 0x0000ffff;
            csum = csum + (csum3 & 0x0000ffff);
          }
        }
        csum = ~csum;
        csum1 = csum & 0xff00;
        csum1 = csum1 >> 8;
        csum2 = csum & 0x00ff;


        txarray[36] =  csum1 & 0x00ff; // Header Checksum
        txarray[37] =  csum2 & 0x00ff; 

        // Data
        for(i=42;i<length;i++)
        {
          txarray[i] = *(Packet+i);
        }

        result = pcap_sendpacket(info,txarray,length);
      }
      else
      {
        result = 1; // Reserve f�r Sp�ter.
      }
    }

    //TCP-IP-Datenpaket
    if(*(Packet+23) == 6) 
    {
      //Modbus TCP Request Auf Port 502 (1f6)
      if((*(Packet+36) == 0x01) && (*(Packet+37) == 0xf6)/* && (*(Packet+44) == 0x00) && (*(Packet+45) == 0x00)*/)
      {
        //Modbus TCP Request
        
        //ACK
        if((*(Packet+47)&&0x10 == 0x10))
        {
          result = 6;
        }
        //SYN
        if((*(Packet+47)&&0x02 == 0x02))
        {
          result = 4;
        }
        //FIN
        if((*(Packet+47)&&0x01 == 0x01))
        {
          result = 5;
        }
        //RST
        if((*(Packet+47)&&0x04 == 0x04))
        {
          result = 7;
        }
      }
    }

    //UDP-IP-Datenpaket
    if(*(Packet+23) == 17) 
    {
      //Modbus UDP Request
      if((*(Packet+36) == 0x01) && (*(Packet+37) == 0xf6)/* && (*(Packet+44) == 0x00) && (*(Packet+45) == 0x00)*/)
      {
        //Modbus UDP UC
        //Modbus UDP BC
        //Modbus UDP MC
      }
    }
  }

  //ARP-Request
  if((*(Packet+12) == 8) && (*(Packet+13) == 6))
  {
    if((*(Packet+20) == 0) && (*(Packet+21) == 1))
    {
      if((IPMUSTER[0] == *(Packet+38)) && (IPMUSTER[1] == *(Packet+39))) // Anfragen auf IP-Adresse pr�fen
      {
        txarray[6] = MACMUSTER[0];   // Source MAC 1
        txarray[7] = MACMUSTER[1];   // Source MAC 2
        txarray[8] = MACMUSTER[2];   // Source MAC 3
        txarray[9] = MACMUSTER[3];   // Source MAC 4
        txarray[10] = *(Packet+40);  // Source MAC 5
        txarray[11] = *(Packet+41);  // Source MAC 6
        txarray[0] = *(Packet+6);   // Dest. MAC 1
        txarray[1] = *(Packet+7);   // Dest. MAC 2
        txarray[2] = *(Packet+8);   // Dest. MAC 3
        txarray[3] = *(Packet+9);   // Dest. MAC 4
        txarray[4] = *(Packet+10);  // Dest. MAC 5
        txarray[5] = *(Packet+11);  // Dest. MAC 6
        
        txarray[12] = 0x08;
        txarray[13] = 0x06;
        txarray[14] = 0x00;
        txarray[15] = 0x01;
        txarray[16] = 0x08;
        txarray[17] = 0x00;
        txarray[18] = 0x06;
        txarray[19] = 0x04;
        txarray[20] = 0x00;
        txarray[21] = 0x02;
        
        txarray[22] = txarray[6]; // Antwort MAC
        txarray[23] = txarray[7];
        txarray[24] = txarray[8];
        txarray[25] = txarray[9];
        txarray[26] = txarray[10];
        txarray[27] = txarray[11];
        
        txarray[28] = *(Packet+38); // Antwort IP
        txarray[29] = *(Packet+39);
        txarray[30] = *(Packet+40);
        txarray[31] = *(Packet+41);

        txarray[32] = *(Packet+22); // Frage MAC
        txarray[33] = *(Packet+23);
        txarray[34] = *(Packet+24);
        txarray[35] = *(Packet+25);
        txarray[36] = *(Packet+26);
        txarray[37] = *(Packet+27);
        
        txarray[38] = *(Packet+28); // Frage IP
        txarray[39] = *(Packet+29);
        txarray[40] = *(Packet+30);
        txarray[41] = *(Packet+31);
        
        result = pcap_sendpacket(info,txarray,42);
      }
    }
    else
    {
      result = 1; // ARP-Rest
    }
  }
  return(result);
}

// Hauptfunktion 
int mainWREmu()
{
  pcap_t *info;
  char *device ="eth1";
  char error[PCAP_ERRBUF_SIZE];
  const u_char *Packet;
  struct pcap_pkthdr data;
  int n;
  int result;
  
  // Datenarray f�r Wechselrichter  
  struct WR Datenarray[MAXWR];

  // Initialisierung der Struktur mit Positionsnummer
  for (n=0;n < MAXWR ;n++)
  {
    Datenarray[n].pos = (n+1);
  }

  // �ffne Ethernet-Schnittstelle
  info = pcap_open_live(device,1500,1,100,error);
 
  // Solange die Schnittstelle aktiv ist.
  while(info)
  {
    // Datenpaket aus dem Puffer holen
    Packet = pcap_next(info,&data);
    if(Packet != 0)
    {
      // Analyse und Reaktion
      result = SelectPaket(Packet,data.len,Datenarray,info);
      
      // Datenpaket zur�cksetzen
      Packet = 0;
    }
  }
  printf("\n");
  pcap_close(info);
  return(result);
}