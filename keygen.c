#include "keygen.h"
#include "opendefs.h"
#include "opentimers.h"
#include "sixtop.h"
#include "packetfunctions.h"
#include "openserial.h"
#include "neighbors.h"
#include "scheduler.h"
#include "idmanager.h"
#include "IEEE802154E.h"
#include "IEEE802154.h"
#include "openqueue.h"
#include "windows_projective.h"
#include "openrandom.h"
#include "sha1.h"
#include "MD5.h"
#include "bsp_timer.h"

//=========================== variables =======================================

keygen_vars_t keygen_vars;

const uint8_t CA_public[2*uECC_BYTES] = {0x6b, 0x6a, 0x3d, 0x74, 0xd8, 0x55, 0x3, 0x31, 0xe4, 0xf2,
                                                0xaf, 0x3d, 0x3f, 0x1, 0x1d, 0x12, 0x54, 0x83, 0xd9, 0x21,
                                                0xbb, 0x8d, 0xa, 0x75, 0xb7, 0xdf, 0xfc, 0x45, 0xa7, 0x3f,
                                                0xc5, 0xe7, 0x54, 0x68, 0xed, 0xea, 0x7d, 0xc6, 0xef, 0x8e};

//=========================== prototypes ======================================

void keygen_timer_cb(opentimer_id_t id);
void keygen_task_cb(void);
void send_Data(void);
void send_check(void);
void compute_shared_key(void);

//=========================== public ==========================================

void keygen_init(void)
{
  keygen_vars.my_id = idmanager_getMyID(ADDR_16B)->addr_16b[1];
  int i;
  switch (keygen_vars.my_id)
  {
  case NODE_1:
    //wait time
    keygen_vars.wait_distance = 1;
    //cert
    for(i=0;i<20;i++)
    {
      keygen_vars.my_cert[i] = 0x11;
    }
    //da
    keygen_vars.my_da[0]=0x1c;keygen_vars.my_da[1]=0xdf;keygen_vars.my_da[2]=0xcc;keygen_vars.my_da[3]=0x1d;
    keygen_vars.my_da[4]=0xd;keygen_vars.my_da[5]=0xe6;keygen_vars.my_da[6]=0xbf;keygen_vars.my_da[7]=0xd4;
    keygen_vars.my_da[8]=0x9e;keygen_vars.my_da[9]=0xa1;keygen_vars.my_da[10]=0x7e;keygen_vars.my_da[11]=0x47;
    keygen_vars.my_da[12]=0x73;keygen_vars.my_da[13]=0x86;keygen_vars.my_da[14]=0xc6;keygen_vars.my_da[15]=0xef;
    keygen_vars.my_da[16]=0xa5;keygen_vars.my_da[17]=0x94;keygen_vars.my_da[18]=0xf7;keygen_vars.my_da[19]=0x7e;
    //Qa
    keygen_vars.my_Qa[0]=0xe9;keygen_vars.my_Qa[1]=0xb1;keygen_vars.my_Qa[2]=0x0;keygen_vars.my_Qa[3]=0x35;
    keygen_vars.my_Qa[4]=0xc8;keygen_vars.my_Qa[5]=0xec;keygen_vars.my_Qa[6]=0x5b;keygen_vars.my_Qa[7]=0xd3;
    keygen_vars.my_Qa[8]=0x54;keygen_vars.my_Qa[9]=0x13;keygen_vars.my_Qa[10]=0xb0;keygen_vars.my_Qa[11]=0xac;
    keygen_vars.my_Qa[12]=0x2;keygen_vars.my_Qa[13]=0x27;keygen_vars.my_Qa[14]=0x14;keygen_vars.my_Qa[15]=0x1;
    keygen_vars.my_Qa[16]=0x85;keygen_vars.my_Qa[17]=0x32;keygen_vars.my_Qa[18]=0xed;keygen_vars.my_Qa[19]=0x67;
    keygen_vars.my_Qa[20]=0xdb;keygen_vars.my_Qa[21]=0x5a;keygen_vars.my_Qa[22]=0xc5;keygen_vars.my_Qa[23]=0x9f;
    keygen_vars.my_Qa[24]=0xaa;keygen_vars.my_Qa[25]=0x5a;keygen_vars.my_Qa[26]=0xb1;keygen_vars.my_Qa[27]=0xcd;
    keygen_vars.my_Qa[28]=0x65;keygen_vars.my_Qa[29]=0xe3;keygen_vars.my_Qa[30]=0x99;keygen_vars.my_Qa[31]=0xaf;
    keygen_vars.my_Qa[32]=0x3d;keygen_vars.my_Qa[33]=0x4c;keygen_vars.my_Qa[34]=0x93;keygen_vars.my_Qa[35]=0x55;
    keygen_vars.my_Qa[36]=0xb4;keygen_vars.my_Qa[37]=0xf4;keygen_vars.my_Qa[38]=0xed;keygen_vars.my_Qa[39]=0xb2;
    //Pa
    keygen_vars.my_Pa[0]=0x67;keygen_vars.my_Pa[1]=0x1f;keygen_vars.my_Pa[2]=0x93;keygen_vars.my_Pa[3]=0x54;keygen_vars.my_Pa[4]=0x40;
    keygen_vars.my_Pa[5]=0xd4;keygen_vars.my_Pa[6]=0xb4;keygen_vars.my_Pa[7]=0xbb;keygen_vars.my_Pa[8]=0xa0;keygen_vars.my_Pa[9]=0x1;
    keygen_vars.my_Pa[10]=0xf4;keygen_vars.my_Pa[11]=0x52;keygen_vars.my_Pa[12]=0x96;keygen_vars.my_Pa[13]=0xbb;keygen_vars.my_Pa[14]=0x13;
    keygen_vars.my_Pa[15]=0xe7;keygen_vars.my_Pa[16]=0x8a;keygen_vars.my_Pa[17]=0x52;keygen_vars.my_Pa[18]=0xa5;keygen_vars.my_Pa[19]=0xff;
    keygen_vars.my_Pa[20]=0x87;keygen_vars.my_Pa[21]=0x6a;keygen_vars.my_Pa[22]=0x6d;keygen_vars.my_Pa[23]=0xd2;keygen_vars.my_Pa[24]=0x52;
    keygen_vars.my_Pa[25]=0x58;keygen_vars.my_Pa[26]=0x9e;keygen_vars.my_Pa[27]=0x6a;keygen_vars.my_Pa[28]=0x19;keygen_vars.my_Pa[29]=0x12;
    keygen_vars.my_Pa[30]=0x19;keygen_vars.my_Pa[31]=0x1d;keygen_vars.my_Pa[32]=0x6;keygen_vars.my_Pa[33]=0xe3;keygen_vars.my_Pa[34]=0x5a;
    keygen_vars.my_Pa[35]=0xb8;keygen_vars.my_Pa[36]=0xcd;keygen_vars.my_Pa[37]=0xb1;keygen_vars.my_Pa[38]=0x9f;keygen_vars.my_Pa[39]=0x3d;
    break;
  case NODE_2:
    //wait time
    keygen_vars.wait_distance = 1;
    //cert
    for(i=0;i<20;i++)
    {
      keygen_vars.my_cert[i] = 0x11;
    }
    //da
    keygen_vars.my_da[0]=0x1c;keygen_vars.my_da[1]=0xdf;keygen_vars.my_da[2]=0xcc;keygen_vars.my_da[3]=0x1d;
    keygen_vars.my_da[4]=0x6c;keygen_vars.my_da[5]=0xf6;keygen_vars.my_da[6]=0xea;keygen_vars.my_da[7]=0xf;
    keygen_vars.my_da[8]=0x71;keygen_vars.my_da[9]=0x77;keygen_vars.my_da[10]=0xbd;keygen_vars.my_da[11]=0x2b;
    keygen_vars.my_da[12]=0xc5;keygen_vars.my_da[13]=0xce;keygen_vars.my_da[14]=0x31;keygen_vars.my_da[15]=0x6;
    keygen_vars.my_da[16]=0xae;keygen_vars.my_da[17]=0x22;keygen_vars.my_da[18]=0x79;keygen_vars.my_da[19]=0xb0;
    //Qa
    keygen_vars.my_Qa[0]=0xe4;keygen_vars.my_Qa[1]=0x9f;keygen_vars.my_Qa[2]=0x80;keygen_vars.my_Qa[3]=0x9c;
    keygen_vars.my_Qa[4]=0x86;keygen_vars.my_Qa[5]=0xde;keygen_vars.my_Qa[6]=0xfe;keygen_vars.my_Qa[7]=0x5;
    keygen_vars.my_Qa[8]=0xb0;keygen_vars.my_Qa[9]=0x17;keygen_vars.my_Qa[10]=0x14;keygen_vars.my_Qa[11]=0x15;
    keygen_vars.my_Qa[12]=0x46;keygen_vars.my_Qa[13]=0x26;keygen_vars.my_Qa[14]=0x99;keygen_vars.my_Qa[15]=0xe0;
    keygen_vars.my_Qa[16]=0xa1;keygen_vars.my_Qa[17]=0xc6;keygen_vars.my_Qa[18]=0xf7;keygen_vars.my_Qa[19]=0xd0;
    keygen_vars.my_Qa[20]=0x8e;keygen_vars.my_Qa[21]=0xe6;keygen_vars.my_Qa[22]=0xb0;keygen_vars.my_Qa[23]=0x4d;
    keygen_vars.my_Qa[24]=0x27;keygen_vars.my_Qa[25]=0x1b;keygen_vars.my_Qa[26]=0xf2;keygen_vars.my_Qa[27]=0x53;
    keygen_vars.my_Qa[28]=0xa6;keygen_vars.my_Qa[29]=0xfe;keygen_vars.my_Qa[30]=0xe6;keygen_vars.my_Qa[31]=0xd6;
    keygen_vars.my_Qa[32]=0xc;keygen_vars.my_Qa[33]=0xfa;keygen_vars.my_Qa[34]=0xb6;keygen_vars.my_Qa[35]=0xff;
    keygen_vars.my_Qa[36]=0x5b;keygen_vars.my_Qa[37]=0x5d;keygen_vars.my_Qa[38]=0xc8;keygen_vars.my_Qa[39]=0x2;
    //Pa
    keygen_vars.my_Pa[0]=0x9;keygen_vars.my_Pa[1]=0xc5;keygen_vars.my_Pa[2]=0xf1;keygen_vars.my_Pa[3]=0xb8;keygen_vars.my_Pa[4]=0xf0;
    keygen_vars.my_Pa[5]=0x98;keygen_vars.my_Pa[6]=0x9c;keygen_vars.my_Pa[7]=0xb4;keygen_vars.my_Pa[8]=0x18;keygen_vars.my_Pa[9]=0x84;
    keygen_vars.my_Pa[10]=0x50;keygen_vars.my_Pa[11]=0x11;keygen_vars.my_Pa[12]=0x6a;keygen_vars.my_Pa[13]=0x6;keygen_vars.my_Pa[14]=0xc5;
    keygen_vars.my_Pa[15]=0xba;keygen_vars.my_Pa[16]=0x5a;keygen_vars.my_Pa[17]=0xf1;keygen_vars.my_Pa[18]=0x82;keygen_vars.my_Pa[19]=0xa0;
    keygen_vars.my_Pa[20]=0x18;keygen_vars.my_Pa[21]=0x3d;keygen_vars.my_Pa[22]=0x12;keygen_vars.my_Pa[23]=0x60;keygen_vars.my_Pa[24]=0xe5;
    keygen_vars.my_Pa[25]=0x26;keygen_vars.my_Pa[26]=0xa8;keygen_vars.my_Pa[27]=0x40;keygen_vars.my_Pa[28]=0xa8;keygen_vars.my_Pa[29]=0x79;
    keygen_vars.my_Pa[30]=0x38;keygen_vars.my_Pa[31]=0x1f;keygen_vars.my_Pa[32]=0xb6;keygen_vars.my_Pa[33]=0x92;keygen_vars.my_Pa[34]=0x1e;
    keygen_vars.my_Pa[35]=0xe5;keygen_vars.my_Pa[36]=0x73;keygen_vars.my_Pa[37]=0xbc;keygen_vars.my_Pa[38]=0xe2;keygen_vars.my_Pa[39]=0xd2;
    break;
    
  case NODE_3:
    //wait time
    keygen_vars.wait_distance = 2;
    //cert
    for(i=0;i<20;i++)
    {
      keygen_vars.my_cert[i] = 0x11;
    }
     //da
    keygen_vars.my_da[0]=0x1c;keygen_vars.my_da[1]=0xdf;keygen_vars.my_da[2]=0xcc;keygen_vars.my_da[3]=0x1d;
    keygen_vars.my_da[4]=0xcc;keygen_vars.my_da[5]=0x7;keygen_vars.my_da[6]=0x14;keygen_vars.my_da[7]=0x4a;
    keygen_vars.my_da[8]=0x44;keygen_vars.my_da[9]=0x4d;keygen_vars.my_da[10]=0xfc;keygen_vars.my_da[11]=0x10;
    keygen_vars.my_da[12]=0x18;keygen_vars.my_da[13]=0x15;keygen_vars.my_da[14]=0x9b;keygen_vars.my_da[15]=0x1d;
    keygen_vars.my_da[16]=0xb6;keygen_vars.my_da[17]=0xaf;keygen_vars.my_da[18]=0xfb;keygen_vars.my_da[19]=0xe2;
    
    //Qa
    keygen_vars.my_Qa[0]=0x64;keygen_vars.my_Qa[1]=0x91;keygen_vars.my_Qa[2]=0xf8;keygen_vars.my_Qa[3]=0xb9;
    keygen_vars.my_Qa[4]=0x86;keygen_vars.my_Qa[5]=0xc6;keygen_vars.my_Qa[6]=0x1f;keygen_vars.my_Qa[7]=0x3d;
    keygen_vars.my_Qa[8]=0x94;keygen_vars.my_Qa[9]=0x30;keygen_vars.my_Qa[10]=0x96;keygen_vars.my_Qa[11]=0xc5;
    keygen_vars.my_Qa[12]=0x29;keygen_vars.my_Qa[13]=0x8d;keygen_vars.my_Qa[14]=0xfb;keygen_vars.my_Qa[15]=0x8e;
    keygen_vars.my_Qa[16]=0x53;keygen_vars.my_Qa[17]=0xe7;keygen_vars.my_Qa[18]=0xb5;keygen_vars.my_Qa[19]=0x45;
    keygen_vars.my_Qa[20]=0x2d;keygen_vars.my_Qa[21]=0x63;keygen_vars.my_Qa[22]=0x60;keygen_vars.my_Qa[23]=0xe6;
    keygen_vars.my_Qa[24]=0xe4;keygen_vars.my_Qa[25]=0xc5;keygen_vars.my_Qa[26]=0xc3;keygen_vars.my_Qa[27]=0x79;
    keygen_vars.my_Qa[28]=0x12;keygen_vars.my_Qa[29]=0x3d;keygen_vars.my_Qa[30]=0xbf;keygen_vars.my_Qa[31]=0xbc;
    keygen_vars.my_Qa[32]=0x45;keygen_vars.my_Qa[33]=0x50;keygen_vars.my_Qa[34]=0xeb;keygen_vars.my_Qa[35]=0xd4;
    keygen_vars.my_Qa[36]=0x92;keygen_vars.my_Qa[37]=0x14;keygen_vars.my_Qa[38]=0x50;keygen_vars.my_Qa[39]=0x3a;
    //Pa
    keygen_vars.my_Pa[0]=0xb0;keygen_vars.my_Pa[1]=0x28;keygen_vars.my_Pa[2]=0x54;keygen_vars.my_Pa[3]=0xd3;keygen_vars.my_Pa[4]=0x92;
    keygen_vars.my_Pa[5]=0xe7;keygen_vars.my_Pa[6]=0x74;keygen_vars.my_Pa[7]=0xbe;keygen_vars.my_Pa[8]=0x87;keygen_vars.my_Pa[9]=0x5;
    keygen_vars.my_Pa[10]=0xd8;keygen_vars.my_Pa[11]=0x47;keygen_vars.my_Pa[12]=0x41;keygen_vars.my_Pa[13]=0x72;keygen_vars.my_Pa[14]=0x4c;
    keygen_vars.my_Pa[15]=0x48;keygen_vars.my_Pa[16]=0xc;keygen_vars.my_Pa[17]=0xe7;keygen_vars.my_Pa[18]=0xc6;keygen_vars.my_Pa[19]=0xcd;
    keygen_vars.my_Pa[20]=0x26;keygen_vars.my_Pa[21]=0xd3;keygen_vars.my_Pa[22]=0xf4;keygen_vars.my_Pa[23]=0x38;keygen_vars.my_Pa[24]=0x92;
    keygen_vars.my_Pa[25]=0x6;keygen_vars.my_Pa[26]=0x25;keygen_vars.my_Pa[27]=0x9b;keygen_vars.my_Pa[28]=0x93;keygen_vars.my_Pa[29]=0xaa;
    keygen_vars.my_Pa[30]=0x2a;keygen_vars.my_Pa[31]=0x1c;keygen_vars.my_Pa[32]=0x48;keygen_vars.my_Pa[33]=0x49;keygen_vars.my_Pa[34]=0xe7;
    keygen_vars.my_Pa[35]=0xd2;keygen_vars.my_Pa[36]=0x9c;keygen_vars.my_Pa[37]=0x2f;keygen_vars.my_Pa[38]=0x55;keygen_vars.my_Pa[39]=0x8;
    break;
    
  case NODE_4:
    //wait time
    keygen_vars.wait_distance = 3;
    //cert
    for(i=0;i<20;i++)
    {
      keygen_vars.my_cert[i] = 0x11;
    }
    //da
    keygen_vars.my_da[0]=0x1c;keygen_vars.my_da[1]=0xdf;keygen_vars.my_da[2]=0xcc;keygen_vars.my_da[3]=0x1e;
    keygen_vars.my_da[4]=0x2b;keygen_vars.my_da[5]=0x17;keygen_vars.my_da[6]=0x3e;keygen_vars.my_da[7]=0x85;
    keygen_vars.my_da[8]=0x17;keygen_vars.my_da[9]=0x24;keygen_vars.my_da[10]=0x3a;keygen_vars.my_da[11]=0xf4;
    keygen_vars.my_da[12]=0x6a;keygen_vars.my_da[13]=0x5d;keygen_vars.my_da[14]=0x5;keygen_vars.my_da[15]=0x34;
    keygen_vars.my_da[16]=0xbf;keygen_vars.my_da[17]=0x3d;keygen_vars.my_da[18]=0x7e;keygen_vars.my_da[19]=0x14;
    //Qa
    keygen_vars.my_Qa[0]=0x5e;keygen_vars.my_Qa[1]=0x19;keygen_vars.my_Qa[2]=0xed;keygen_vars.my_Qa[3]=0xfe;
    keygen_vars.my_Qa[4]=0x4;keygen_vars.my_Qa[5]=0x5b;keygen_vars.my_Qa[6]=0x26;keygen_vars.my_Qa[7]=0x7;
    keygen_vars.my_Qa[8]=0xb1;keygen_vars.my_Qa[9]=0xcb;keygen_vars.my_Qa[10]=0x34;keygen_vars.my_Qa[11]=0x12;
    keygen_vars.my_Qa[12]=0xf1;keygen_vars.my_Qa[13]=0x48;keygen_vars.my_Qa[14]=0xc8;keygen_vars.my_Qa[15]=0x62;
    keygen_vars.my_Qa[16]=0x85;keygen_vars.my_Qa[17]=0xaf;keygen_vars.my_Qa[18]=0xa7;keygen_vars.my_Qa[19]=0x1e;
    keygen_vars.my_Qa[20]=0xe6;keygen_vars.my_Qa[21]=0xfc;keygen_vars.my_Qa[22]=0x16;keygen_vars.my_Qa[23]=0xa9;
    keygen_vars.my_Qa[24]=0xcb;keygen_vars.my_Qa[25]=0xc0;keygen_vars.my_Qa[26]=0x2b;keygen_vars.my_Qa[27]=0x5f;
    keygen_vars.my_Qa[28]=0x40;keygen_vars.my_Qa[29]=0xe2;keygen_vars.my_Qa[30]=0x8e;keygen_vars.my_Qa[31]=0x5a;
    keygen_vars.my_Qa[32]=0x65;keygen_vars.my_Qa[33]=0xff;keygen_vars.my_Qa[34]=0x61;keygen_vars.my_Qa[35]=0x11;
    keygen_vars.my_Qa[36]=0x9;keygen_vars.my_Qa[37]=0x8d;keygen_vars.my_Qa[38]=0x4;keygen_vars.my_Qa[39]=0x6b;
    //Pa
    keygen_vars.my_Pa[0]=0xa7;keygen_vars.my_Pa[1]=0xb1;keygen_vars.my_Pa[2]=0xb6;keygen_vars.my_Pa[3]=0x4f;keygen_vars.my_Pa[4]=0x5d;
    keygen_vars.my_Pa[5]=0xd9;keygen_vars.my_Pa[6]=0x18;keygen_vars.my_Pa[7]=0xcb;keygen_vars.my_Pa[8]=0x9;keygen_vars.my_Pa[9]=0xca;
    keygen_vars.my_Pa[10]=0xdc;keygen_vars.my_Pa[11]=0xa3;keygen_vars.my_Pa[12]=0x57;keygen_vars.my_Pa[13]=0x1c;keygen_vars.my_Pa[14]=0xff;
    keygen_vars.my_Pa[15]=0x28;keygen_vars.my_Pa[16]=0x97;keygen_vars.my_Pa[17]=0x7;keygen_vars.my_Pa[18]=0x39;keygen_vars.my_Pa[19]=0x96;
    keygen_vars.my_Pa[20]=0x25;keygen_vars.my_Pa[21]=0x12;keygen_vars.my_Pa[22]=0xbc;keygen_vars.my_Pa[23]=0x76;keygen_vars.my_Pa[24]=0xdb;
    keygen_vars.my_Pa[25]=0xa8;keygen_vars.my_Pa[26]=0x36;keygen_vars.my_Pa[27]=0xf4;keygen_vars.my_Pa[28]=0x5e;keygen_vars.my_Pa[29]=0xe7;
    keygen_vars.my_Pa[30]=0x99;keygen_vars.my_Pa[31]=0xc0;keygen_vars.my_Pa[32]=0x63;keygen_vars.my_Pa[33]=0x8f;keygen_vars.my_Pa[34]=0x83;
    keygen_vars.my_Pa[35]=0x28;keygen_vars.my_Pa[36]=0x6b;keygen_vars.my_Pa[37]=0x72;keygen_vars.my_Pa[38]=0x4a;keygen_vars.my_Pa[39]=0xca;
    break;
    
  case NODE_5:
    //wait time
    keygen_vars.wait_distance = 4;
    //cert
    for(i=0;i<20;i++)
    {
      keygen_vars.my_cert[i] = 0x11;
    }
    //da
    keygen_vars.my_da[0]=0x1c;keygen_vars.my_da[1]=0xdf;keygen_vars.my_da[2]=0xcc;keygen_vars.my_da[3]=0x1e;
    keygen_vars.my_da[4]=0x8a;keygen_vars.my_da[5]=0x27;keygen_vars.my_da[6]=0x68;keygen_vars.my_da[7]=0xbf;
    keygen_vars.my_da[8]=0xe9;keygen_vars.my_da[9]=0xfa;keygen_vars.my_da[10]=0x79;keygen_vars.my_da[11]=0xd8;
    keygen_vars.my_da[12]=0xbc;keygen_vars.my_da[13]=0xa4;keygen_vars.my_da[14]=0x6f;keygen_vars.my_da[15]=0x4b;
    keygen_vars.my_da[16]=0xc7;keygen_vars.my_da[17]=0xcb;keygen_vars.my_da[18]=0x0;keygen_vars.my_da[19]=0x46;
    
    //Qa
    keygen_vars.my_Qa[0]=0xe3;keygen_vars.my_Qa[1]=0x6e;keygen_vars.my_Qa[2]=0x4e;keygen_vars.my_Qa[3]=0x42;
    keygen_vars.my_Qa[4]=0x21;keygen_vars.my_Qa[5]=0x10;keygen_vars.my_Qa[6]=0x4e;keygen_vars.my_Qa[7]=0xd8;
    keygen_vars.my_Qa[8]=0x99;keygen_vars.my_Qa[9]=0xf5;keygen_vars.my_Qa[10]=0xac;keygen_vars.my_Qa[11]=0x6a;
    keygen_vars.my_Qa[12]=0xd4;keygen_vars.my_Qa[13]=0x41;keygen_vars.my_Qa[14]=0x33;keygen_vars.my_Qa[15]=0xa7;
    keygen_vars.my_Qa[16]=0x9d;keygen_vars.my_Qa[17]=0xb9;keygen_vars.my_Qa[18]=0xec;keygen_vars.my_Qa[19]=0xa9;
    keygen_vars.my_Qa[20]=0x1d;keygen_vars.my_Qa[21]=0xdd;keygen_vars.my_Qa[22]=0x5d;keygen_vars.my_Qa[23]=0xb7;
    keygen_vars.my_Qa[24]=0x2b;keygen_vars.my_Qa[25]=0xd0;keygen_vars.my_Qa[26]=0xb1;keygen_vars.my_Qa[27]=0x66;
    keygen_vars.my_Qa[28]=0x44;keygen_vars.my_Qa[29]=0xf;keygen_vars.my_Qa[30]=0xbd;keygen_vars.my_Qa[31]=0x39;
    keygen_vars.my_Qa[32]=0xd1;keygen_vars.my_Qa[33]=0x2f;keygen_vars.my_Qa[34]=0x5e;keygen_vars.my_Qa[35]=0xa1;
    keygen_vars.my_Qa[36]=0xc1;keygen_vars.my_Qa[37]=0x16;keygen_vars.my_Qa[38]=0x92;keygen_vars.my_Qa[39]=0x54;
    //Pa
    keygen_vars.my_Pa[0]=0x7f;keygen_vars.my_Pa[1]=0xc4;keygen_vars.my_Pa[2]=0xdb;keygen_vars.my_Pa[3]=0x35;keygen_vars.my_Pa[4]=0x0;
    keygen_vars.my_Pa[5]=0xd4;keygen_vars.my_Pa[6]=0xba;keygen_vars.my_Pa[7]=0x2;keygen_vars.my_Pa[8]=0x8f;keygen_vars.my_Pa[9]=0x68;
    keygen_vars.my_Pa[10]=0x72;keygen_vars.my_Pa[11]=0x5b;keygen_vars.my_Pa[12]=0x68;keygen_vars.my_Pa[13]=0x2d;keygen_vars.my_Pa[14]=0x19;
    keygen_vars.my_Pa[15]=0xab;keygen_vars.my_Pa[16]=0xe4;keygen_vars.my_Pa[17]=0xd1;keygen_vars.my_Pa[18]=0x11;keygen_vars.my_Pa[19]=0x10;
    keygen_vars.my_Pa[20]=0xfd;keygen_vars.my_Pa[21]=0x1;keygen_vars.my_Pa[22]=0x94;keygen_vars.my_Pa[23]=0xd1;keygen_vars.my_Pa[24]=0x72;
    keygen_vars.my_Pa[25]=0x69;keygen_vars.my_Pa[26]=0x21;keygen_vars.my_Pa[27]=0xb9;keygen_vars.my_Pa[28]=0x3;keygen_vars.my_Pa[29]=0xb6;
    keygen_vars.my_Pa[30]=0x45;keygen_vars.my_Pa[31]=0x12;keygen_vars.my_Pa[32]=0xd8;keygen_vars.my_Pa[33]=0x19;keygen_vars.my_Pa[34]=0xe0;
    keygen_vars.my_Pa[35]=0x1f;keygen_vars.my_Pa[36]=0x8c;keygen_vars.my_Pa[37]=0xfc;keygen_vars.my_Pa[38]=0xd4;keygen_vars.my_Pa[39]=0x9f;
    break;
    
  default:
    break;
    
  }
  
    //keygen_vars.period = KEYGEN_PERIOD_MS+(keygen_vars.wait_distance-1)*KEYGEN_RUN_TIME;
  keygen_vars.period = 150;
  
  keygen_vars.timerId                    = opentimers_start(
      keygen_vars.period,
      TIMER_PERIODIC,TIME_MS,
      keygen_timer_cb
   );
  
}

void keygen_timer_cb(opentimer_id_t id)
{
  scheduler_push_task(keygen_task_cb, TASKPRIO_SIXTOP_NOTIF_RX);
  
}

void keygen_task_cb(void)
{
  uint8_t time[5];
  ieee154e_getAsn(time);
  uint16_t bytes0and1;
  bytes0and1 = time[0]+256*time[1];
  if((idmanager_getIsDAGroot() == FALSE) && (ieee154e_isSynch() == 1)&&(bytes0and1>4000+(keygen_vars.wait_distance-1)*KEYGEN_RUN_TIME))
  {
    scheduler_push_task(send_Data, TASKPRIO_NONE);
    opentimers_stop(keygen_vars.timerId);
  }
}

void send_Data(void)
{
  uint8_t time[5];
  uint16_t bytes0and1,bytes2and3;
  ieee154e_getAsn(time);
  bytes0and1 = time[0]+256*time[1];
  bytes2and3 = time[2]+256*time[3];
  openserial_printError(COMPONENT_SIXTOP,90,(errorparameter_t)bytes2and3,(errorparameter_t)bytes0and1);
  /*uint16_t time_1,time_2;
  time_1 = bsp_timer_get_currentValue();*/
  //generate nonce
  uint16_t r[3];
  int i;
  for(i=0;i<3;i++)
  {
    r[i] = openrandom_get16b();
    keygen_vars.my_nonce[2*i] = (r[i]) & 0xff;
    keygen_vars.my_nonce[2*i + 1] = (r[i] >> (8 * 1)) & 0xff;
  }
  /*time_2 = bsp_timer_get_currentValue();
  openserial_printError(COMPONENT_SIXTOP,80,(errorparameter_t)time_1,(errorparameter_t)time_2);
  ieee154e_getAsn(time);
  bytes0and1 = time[0]+256*time[1];
  bytes2and3 = time[2]+256*time[3];
  openserial_printError(COMPONENT_SIXTOP,90,(errorparameter_t)bytes2and3,(errorparameter_t)bytes0and1);*/
  //generate mic
  /*ieee154e_getAsn(time);
  bytes0and1 = time[0]+256*time[1];
  bytes2and3 = time[2]+256*time[3];
  openserial_printError(COMPONENT_SIXTOP,90,(errorparameter_t)bytes2and3,(errorparameter_t)bytes0and1);
  time_1 = bsp_timer_get_currentValue();*/
  BYTE text1[106];
  for(i=0;i<40;i++)
  {
    text1[i] = keygen_vars.my_Qa[i];
    text1[i+40] = keygen_vars.my_Pa[i];
  }
  for(i=0;i<20;i++)
  {
    text1[i+80] = keygen_vars.my_cert[i];
  }
  for(i=0;i<6;i++)
  {
    text1[i+100] = keygen_vars.my_nonce[i];
  }
  BYTE buf[SHA1_BLOCK_SIZE];
  SHA1_CTX ctx;
  sha1_init(&ctx);
  sha1_update(&ctx, text1, 106);
  sha1_final(&ctx, buf);
  for(i=0;i<20;i++)
  {
    keygen_vars.my_mic[i] = buf[i];
  }
   /*time_2 = bsp_timer_get_currentValue();
  openserial_printError(COMPONENT_SIXTOP,81,(errorparameter_t)time_1,(errorparameter_t)time_2);
  ieee154e_getAsn(time);
  bytes0and1 = time[0]+256*time[1];
  bytes2and3 = time[2]+256*time[3];
  openserial_printError(COMPONENT_SIXTOP,90,(errorparameter_t)bytes2and3,(errorparameter_t)bytes0and1);*/
  //send message 1
  //time_1 = bsp_timer_get_currentValue();
  OpenQueueEntry_t *pkt;
  pkt = openqueue_getFreePacketBuffer(COMPONENT_SIXTOP);
  if (pkt == NULL)
  {
    openserial_printError(COMPONENT_SIXTOP, ERR_NO_FREE_PACKET_BUFFER,
                          (errorparameter_t)0,
                          (errorparameter_t)0);
    return;
  }
  //declare ownership over that packet
  pkt->creator = COMPONENT_SIXTOP;
  pkt->owner = COMPONENT_SIXTOP;
  // some l2 information about this packet
   pkt->l2_frameType = IEEE154_TYPE_DATA;
   if (idmanager_getIsDAGroot() == FALSE)
   {
     icmpv6rpl_getPreferredParentEui64(&(pkt->l2_nextORpreviousHop));
     if (pkt->l2_nextORpreviousHop.type == 0)
     {
       openserial_printInfo(COMPONENT_SECURITY, ERR_SECURITY,
                            (errorparameter_t)pkt->l2_nextORpreviousHop.type,
                            (errorparameter_t)334);
       return;
     }
   }
   else
   {
     memcpy(&(pkt->l2_nextORpreviousHop), &(keygen_vars.last_Neighbor), sizeof(open_addr_t));
     memcpy(&(pkt->l2_keySource), idmanager_getMyID(ADDR_64B), sizeof(open_addr_t));
   }
   packetfunctions_reserveHeaderSize(pkt, 82);
   pkt->payload[0] = PROTOCOL_ID;
   pkt->payload[1] = messeage_frag;
   for(i=0;i<40;i++)
  {
    pkt->payload[i+2] = keygen_vars.my_Qa[i];
    pkt->payload[i+42] = keygen_vars.my_Pa[i];
  }
  sixtop_send(pkt);
  /*ieee154e_getAsn(time);
  bytes0and1 = time[0]+256*time[1];
  bytes2and3 = time[2]+256*time[3];
  openserial_printError(COMPONENT_SIXTOP,90,(errorparameter_t)bytes2and3,(errorparameter_t)bytes0and1);*/
  
  //send message 2
  OpenQueueEntry_t *pkt_2;
  pkt_2 = openqueue_getFreePacketBuffer(COMPONENT_SIXTOP);
  if (pkt_2 == NULL)
  {
    openserial_printError(COMPONENT_SIXTOP, ERR_NO_FREE_PACKET_BUFFER,
                          (errorparameter_t)0,
                          (errorparameter_t)0);
    return;
  }
  //declare ownership over that packet
  pkt_2->creator = COMPONENT_SIXTOP;
  pkt_2->owner = COMPONENT_SIXTOP;
  // some l2 information about this packet
   pkt_2->l2_frameType = IEEE154_TYPE_DATA;
   if (idmanager_getIsDAGroot() == FALSE)
   {
     icmpv6rpl_getPreferredParentEui64(&(pkt_2->l2_nextORpreviousHop));
     if (pkt_2->l2_nextORpreviousHop.type == 0)
     {
       openserial_printInfo(COMPONENT_SECURITY, ERR_SECURITY,
                            (errorparameter_t)pkt_2->l2_nextORpreviousHop.type,
                            (errorparameter_t)334);
       return;
     }
   }
   else
   {
     memcpy(&(pkt_2->l2_nextORpreviousHop), &(keygen_vars.last_Neighbor), sizeof(open_addr_t));
     memcpy(&(pkt_2->l2_keySource), idmanager_getMyID(ADDR_64B), sizeof(open_addr_t));
   }
   packetfunctions_reserveHeaderSize(pkt_2, 47);
   pkt_2->payload[0] = PROTOCOL_ID;
   for(i=0;i<20;i++)
  {
    pkt_2->payload[i+1] = keygen_vars.my_cert[i];
    pkt_2->payload[i+21] = keygen_vars.my_mic[i];
  }
  for(i=0;i<6;i++)
  {
    pkt_2->payload[i+41] = keygen_vars.my_nonce[i];
  }
  sixtop_send(pkt_2);
  /*ieee154e_getAsn(time);
  bytes0and1 = time[0]+256*time[1];
  bytes2and3 = time[2]+256*time[3];
  openserial_printError(COMPONENT_SIXTOP,91,(errorparameter_t)bytes2and3,(errorparameter_t)bytes0and1);*/
  
  /*time_2 = bsp_timer_get_currentValue();
  openserial_printError(COMPONENT_SIXTOP,82,(errorparameter_t)time_1,(errorparameter_t)time_2);*/
}

void keygen_receive(OpenQueueEntry_t *msg)
{
  /*uint8_t time[5];
  uint16_t bytes0and1,bytes2and3;*/
  //uint16_t time_1,time_2;
   if(idmanager_getIsDAGroot() == TRUE)
   {
     if(msg->payload[1] == messeage_frag)
     {
       /*ieee154e_getAsn(time);
       bytes0and1 = time[0]+256*time[1];
       bytes2and3 = time[2]+256*time[3];
       openserial_printError(COMPONENT_SIXTOP,92,(errorparameter_t)bytes2and3,(errorparameter_t)bytes0and1);*/
       int i;
       for(i=0;i<40;i++)
       {
         keygen_vars.his_Qa[i] = msg->payload[i+2];
         keygen_vars.his_Pa[i] = msg->payload[i+42];
       }
       openqueue_freePacketBuffer(msg);
     }
     else if(msg->payload[1] == messeage_check)
     {
       /*ieee154e_getAsn(time);
       bytes0and1 = time[0]+256*time[1];
       bytes2and3 = time[2]+256*time[3];
       openserial_printError(COMPONENT_SIXTOP,97,(errorparameter_t)bytes2and3,(errorparameter_t)bytes0and1);*/
       //openserial_printInfo(COMPONENT_SIXTOP, ERR_UDPTEST, (errorparameter_t)22,(errorparameter_t)(errorparameter_t)22);
       scheduler_push_task(compute_shared_key, TASKPRIO_NONE);
       openqueue_freePacketBuffer(msg);
     }
     else
     {
       /*ieee154e_getAsn(time);
       bytes0and1 = time[0]+256*time[1];
       bytes2and3 = time[2]+256*time[3];
       openserial_printError(COMPONENT_SIXTOP,93,(errorparameter_t)bytes2and3,(errorparameter_t)bytes0and1);*/
       int i;
       for(i=0;i<20;i++)
       {
         keygen_vars.his_cert[i] = msg->payload[i+1];
         keygen_vars.his_mic[i] = msg->payload[i+21];
       }
       for(i=0;i<6;i++)
       {
         keygen_vars.his_nonce[i] = msg->payload[i+41];
       }
       //check mic
         BYTE text1[106];
        for(i=0;i<40;i++)
        {
          text1[i] = keygen_vars.his_Qa[i];
          text1[i+40] = keygen_vars.his_Pa[i];
        }
        for(i=0;i<20;i++)
        {
          text1[i+80] = keygen_vars.his_cert[i];
        }
        for(i=0;i<6;i++)
        {
           text1[i+100] = keygen_vars.his_nonce[i];
        }
        BYTE buf[SHA1_BLOCK_SIZE];
        SHA1_CTX ctx;
        sha1_init(&ctx);
        sha1_update(&ctx, text1, 106);
        sha1_final(&ctx, buf);
        //openserial_printInfo(COMPONENT_SIXTOP, 69, (errorparameter_t)buf[0],(errorparameter_t)(errorparameter_t)keygen_vars.his_mic[0]);
        //check Q
        MD5Context dtx;
        md5Init(&dtx);
        md5Update(&dtx, keygen_vars.his_cert, 20);
        md5Finalize(&dtx);
        uint8_t temp[20], check[40];
        for(i=0;i<4;i++)
        {
           temp[i] = 0;
        }
        for(i=0;i<16;i++)
        {
           temp[i+4] = dtx.digest[i];
        }
        uECC_shared_secret_wp(keygen_vars.his_Pa, temp, check);
         uint8_t x1[20],y1[20],x2[20],y2[20];
         for(i=0;i<20;i++)
         {
           x1[i] = check[i];
           y1[i] = check[i+20];
           x2[i] = CA_public[i];
           y2[i] = CA_public[i+20];
         }
         uECC_point_add_wp(x1,y1,x2,y2);
         //openserial_printInfo(COMPONENT_SIXTOP, 70, (errorparameter_t)keygen_vars.his_Qa[0],(errorparameter_t)(errorparameter_t)x1[0]);
         //send message
         keygen_vars.last_Neighbor = msg->l2_nextORpreviousHop;
         scheduler_push_task(send_Data, TASKPRIO_NONE);
         openqueue_freePacketBuffer(msg);
     }
   }
   else
   {
     if(msg->payload[1] == messeage_frag)
     {
       /*ieee154e_getAsn(time);
       bytes0and1 = time[0]+256*time[1];
       bytes2and3 = time[2]+256*time[3];
       openserial_printError(COMPONENT_SIXTOP,94,(errorparameter_t)bytes2and3,(errorparameter_t)bytes0and1);*/
       int i;
       for(i=0;i<40;i++)
       {
         keygen_vars.his_Qa[i] = msg->payload[i+2];
         keygen_vars.his_Pa[i] = msg->payload[i+42];
       }
       openqueue_freePacketBuffer(msg);
     }
     else
     {
       /*ieee154e_getAsn(time);
       bytes0and1 = time[0]+256*time[1];
       bytes2and3 = time[2]+256*time[3];
       openserial_printError(COMPONENT_SIXTOP,95,(errorparameter_t)bytes2and3,(errorparameter_t)bytes0and1);*/
       int i;
       for(i=0;i<20;i++)
       {
         keygen_vars.his_cert[i] = msg->payload[i+1];
         keygen_vars.his_mic[i] = msg->payload[i+21];
       }
       for(i=0;i<6;i++)
       {
         keygen_vars.his_nonce[i] = msg->payload[i+41];
       }
       //check mic
         //time_1 = bsp_timer_get_currentValue();
         BYTE text1[106];
        for(i=0;i<40;i++)
        {
          text1[i] = keygen_vars.his_Qa[i];
          text1[i+40] = keygen_vars.his_Pa[i];
        }
        for(i=0;i<20;i++)
        {
          text1[i+80] = keygen_vars.his_cert[i];
        }
        for(i=0;i<6;i++)
        {
           text1[i+100] = keygen_vars.his_nonce[i];
        }
        BYTE buf[SHA1_BLOCK_SIZE];
        SHA1_CTX ctx;
        sha1_init(&ctx);
        sha1_update(&ctx, text1, 106);
        sha1_final(&ctx, buf);
        //openserial_printInfo(COMPONENT_SIXTOP, 71, (errorparameter_t)buf[0],(errorparameter_t)(errorparameter_t)keygen_vars.his_mic[0]);
        /*time_2 = bsp_timer_get_currentValue();
        openserial_printError(COMPONENT_SIXTOP,83,(errorparameter_t)time_1,(errorparameter_t)time_2);*/
        //check Q
        /*uint8_t time[5];
        uint16_t bytes0and1,bytes2and3;
        ieee154e_getAsn(time);
        bytes0and1 = time[0]+256*time[1];
        bytes2and3 = time[2]+256*time[3];
        openserial_printError(COMPONENT_SIXTOP,91,(errorparameter_t)bytes2and3,(errorparameter_t)bytes0and1);
        time_1 = bsp_timer_get_currentValue();*/
        MD5Context dtx;
        md5Init(&dtx);
        md5Update(&dtx, keygen_vars.his_cert, 20);
        md5Finalize(&dtx);
        uint8_t temp[20], check[40];
        for(i=0;i<4;i++)
        {
           temp[i] = 0;
        }
        for(i=0;i<16;i++)
        {
           temp[i+4] = dtx.digest[i];
        }
        uECC_shared_secret_wp(keygen_vars.his_Pa, temp, check);
         uint8_t x1[20],y1[20],x2[20],y2[20];
         for(i=0;i<20;i++)
         {
           x1[i] = check[i];
           y1[i] = check[i+20];
           x2[i] = CA_public[i];
           y2[i] = CA_public[i+20];
         }
         uECC_point_add_wp(x1,y1,x2,y2);
         //openserial_printInfo(COMPONENT_SIXTOP, 72, (errorparameter_t)keygen_vars.his_Qa[0],(errorparameter_t)(errorparameter_t)x1[0]);
         /*time_2 = bsp_timer_get_currentValue();
        openserial_printError(COMPONENT_SIXTOP,84,(errorparameter_t)time_1,(errorparameter_t)time_2);
        ieee154e_getAsn(time);
        bytes0and1 = time[0]+256*time[1];
        bytes2and3 = time[2]+256*time[3];
        openserial_printError(COMPONENT_SIXTOP,91,(errorparameter_t)bytes2and3,(errorparameter_t)bytes0and1);*/
         //send message
        //time_1 = bsp_timer_get_currentValue();
         keygen_vars.last_Neighbor = msg->l2_nextORpreviousHop;
         scheduler_push_task(send_check, TASKPRIO_NONE);
         /*time_2 = bsp_timer_get_currentValue();
        openserial_printError(COMPONENT_SIXTOP,85,(errorparameter_t)time_1,(errorparameter_t)time_2);*/
         scheduler_push_task(compute_shared_key, TASKPRIO_NONE);
         // stop time running
         //opentimers_stop(keygen_vars.timerId);
         openqueue_freePacketBuffer(msg);
     }
   }
}

void send_check(void)
{
  /*uint8_t time[5];
  uint16_t bytes0and1,bytes2and3;*/
  OpenQueueEntry_t *pkt;
  
  pkt = openqueue_getFreePacketBuffer(COMPONENT_SIXTOP);
  if (pkt == NULL)
	{
	openserial_printError(COMPONENT_SIXTOP, ERR_NO_FREE_PACKET_BUFFER,
					(errorparameter_t)0,
					(errorparameter_t)0);
	return;
	}
  
  
  //declare ownership over that packet
  pkt->creator = COMPONENT_SIXTOP;
  pkt->owner = COMPONENT_SIXTOP;
  // some l2 information about this packet
  pkt->l2_frameType = IEEE154_TYPE_DATA;
  
  if (idmanager_getIsDAGroot() == FALSE)
  {
    icmpv6rpl_getPreferredParentEui64(&(pkt->l2_nextORpreviousHop));
    if (pkt->l2_nextORpreviousHop.type == 0)
    {
      openserial_printInfo(COMPONENT_SECURITY, ERR_SECURITY,
	    (errorparameter_t)pkt->l2_nextORpreviousHop.type,
		                     (errorparameter_t)334);
      return;
    }
  }
    else
    {
      memcpy(&(pkt->l2_nextORpreviousHop), &(keygen_vars.last_Neighbor), sizeof(open_addr_t));
      memcpy(&(pkt->l2_keySource), idmanager_getMyID(ADDR_64B), sizeof(open_addr_t));
    }
    packetfunctions_reserveHeaderSize(pkt, 2);
    pkt->payload[0] = PROTOCOL_ID;
    pkt->payload[1] = messeage_check;
    sixtop_send(pkt);
    
    /*ieee154e_getAsn(time);
    bytes0and1 = time[0]+256*time[1];
    bytes2and3 = time[2]+256*time[3];
    openserial_printError(COMPONENT_SIXTOP,96,(errorparameter_t)bytes2and3,(errorparameter_t)bytes0and1);*/
}


void compute_shared_key(void)
{
  uint8_t time[5];
  uint16_t bytes0and1,bytes2and3;
  /*ieee154e_getAsn(time);
  bytes0and1 = time[0]+256*time[1];
  bytes2and3 = time[2]+256*time[3];
  openserial_printError(COMPONENT_SIXTOP,92,(errorparameter_t)bytes2and3,(errorparameter_t)bytes0and1);
  uint16_t time_1,time_2;
  time_1 = bsp_timer_get_currentValue();*/
  uECC_shared_secret_wp(keygen_vars.his_Qa,keygen_vars.my_da,keygen_vars.shared_key);
  /*time_2 = bsp_timer_get_currentValue();
  openserial_printError(COMPONENT_SIXTOP,86,(errorparameter_t)time_1,(errorparameter_t)time_2);*/
  ieee154e_getAsn(time);
  bytes0and1 = time[0]+256*time[1];
  bytes2and3 = time[2]+256*time[3];
  openserial_printError(COMPONENT_SIXTOP,92,(errorparameter_t)bytes2and3,(errorparameter_t)bytes0and1);
  openserial_printInfo(COMPONENT_SIXTOP, 73, (errorparameter_t)keygen_vars.shared_key[0],(errorparameter_t)keygen_vars.shared_key[1]);
  openserial_printInfo(COMPONENT_SIXTOP, 73, (errorparameter_t)keygen_vars.shared_key[2],(errorparameter_t)keygen_vars.shared_key[3]);
  openserial_printInfo(COMPONENT_SIXTOP, 73, (errorparameter_t)keygen_vars.shared_key[4],(errorparameter_t)keygen_vars.shared_key[5]);

}
