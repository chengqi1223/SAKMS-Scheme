#include "nodejoin test.h"
#include <stdio.h>
#include <string.h>
#include "openserial.h"
#include "opendefs.h"
#include "bsp_timer.h"
#include "montogomery_pro.h"
#include "windows_projective.h"
#include "MD5.h"
#include "IEEE802154E.h"


//=========================== variables =======================================
const uint8_t CA_public[2*uECC_BYTES] = {0xcc,0x48,0xce,0x4c,0xa,0x6b,0x15,0xd2,0xf4,0x7a,0x5a,0xb,0xc6,0x9a,0x21,0xe2,0x5e,0x59,0x2b,0x45,0x92,0x34,0x17,0x20,0x99,
                                          0xc7,0x58,0x6d,0x30,0x63,0x47,0xec,0x9b,0x7d,0x4f,0x30,0xee,0xc7,0xec,0x43,0xad,0x31,0x32,
                                           0x90,0xb8,0x8b,0xc9,0xa7,0x16,0xd1,0x66,0xd4,0xa,0x7a,0xe2,0xcc,0x9c,0x52,0x97,0xbb,0x34,0x17,0x30,0x5};
const uint8_t Pa[2*uECC_BYTES] = {0x7b,0xcd,0xf0,0xe4,0x52,0x6d,0x7c,0x8a,0xff,0x71,0x3c,0xea,0x7d,0x3f,0x85,0x78,0x56,0x98,0x9a,0x51,0x15,0x5d,0x12,0x71,0x3e,0x56,0xb1,
                                  0xd7,0xe1,0x6e,0xae,0x1a,0xa,0x53,0x73,0x7a,0x89,0x4d,0x25,0xe4,0xed,0x1e,0x85,0xe5,0xff,0xc,
                                  0x26,0x12,0xe3,0x5e,0x70,0xf6,0x11,0x37,0xe8,0x5e,0x1d,0x98,0xf4,0xa4,0x4d,0x3,0x83,0xe6};


//=========================== prototypes ======================================
void nodejoin_mp_test(void);
void nodejoin_wp_test(void);
void nodejoin_mp_test_part2(void);
void nodejoin_wp_test_part2(void);

//=========================== public ==========================================

void nodejoin_test_init(void)
{
  nodejoin_mp_test();
  nodejoin_mp_test_part2();
  //nodejoin_wp_test();
  //nodejoin_wp_test_part2();
}

void nodejoin_mp_test(void)
{
   //change
  uint16_t time_1,time_2;
  time_1 = bsp_timer_get_currentValue();
  
  /*uint8_t time[5];
  ieee154e_getAsn(time);
  uint16_t bytes0and1;
  bytes0and1 = time[0]+256*time[1];
   openserial_printError(COMPONENT_COAPTEST,ERR_COAPTEST,(errorparameter_t)1,(errorparameter_t)bytes0and1);*/
    uint8_t my_cert[20],my_private[32],my_public[64];
    uint8_t k[32] = {0xbf,0x20,0x35,0xbd,0x30,0xa7,0xe6,0x3a,0xbd,0xc6,0xb3,0xab,0x8,0x5c,0xe6,0x33,0xc2,0x24,0x5,0x7a, 0x11,0x22,0x33,0x44,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x1};
    uint8_t w[32] = {0x5b,0xf,0x6c,0x96,0x49,0x5f,0xd,0xb6,0x9b,0xb5,0x77,0x44,0xe8,0x21,0x8b,0x42,0x49,0x49,0xf2,0x4a,0x9f,0x82,0xe1,0xb,0xf4,0x70,0x75,0x85,0x62,0xc2,0x26,0x97};
    int i;
    for(i=0;i<20;i++)
    {
      my_cert[i] = 0x11;
    }
    
    MD5Context ctx;
    md5Init(&ctx);
    md5Update(&ctx,  my_cert, 20);
    md5Finalize(&ctx);
    uint8_t temp[32], check[64];
    for(i=0;i<16;i++)
    {
       temp[i] = 0;
    }
    for(i=0;i<16;i++)
    {
       temp[i+16] = ctx.digest[i];
    }
    uECC_n_operation_mp(my_private, temp, k, w);
    uECC_compute_public_key_mp(my_private, my_public);
    uECC_shared_secret_mp(Pa, temp, check);
    uint8_t x1[32],y1[32],x2[32],y2[32];
    for(i=0;i<32;i++)
    {
        x1[i] = check[i];
        y1[i] = check[i+32];
        x2[i] = CA_public[i];
        y2[i] = CA_public[i+32];
    }
    uECC_point_add_mp(x1,y1,x2,y2);
    
    /*ieee154e_getAsn(time);
    bytes0and1 = time[0]+256*time[1];
   openserial_printError(COMPONENT_COAPTEST,ERR_COAPTEST,(errorparameter_t)2,(errorparameter_t)bytes0and1);*/
    time_2 = bsp_timer_get_currentValue();
    openserial_printInfo(COMPONENT_COAPTEST, ERR_COAPTEST,(errorparameter_t)my_public[0],(errorparameter_t)x1[0]);
      openserial_printError(COMPONENT_ECCM,ERR_ECC,(errorparameter_t)time_1,(errorparameter_t)time_2);
  
}

/*void nodejoin_wp_test(void)
{
  uint16_t time_1,time_2;
  time_1 = bsp_timer_get_currentValue();
  
  uint8_t time[5];
  ieee154e_getAsn(time);
  uint16_t bytes0and1;
  bytes0and1 = time[0]+256*time[1];
   
    uint8_t my_cert[20],my_private[32],my_public[64];
    uint8_t k[32] = {0xbf,0x20,0x35,0xbd,0x30,0xa7,0xe6,0x3a,0xbd,0xc6,0xb3,0xab,0x8,0x5c,0xe6,0x33,0xc2,0x24,0x5,0x7a, 0x11,0x22,0x33,0x44,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x1};
    uint8_t w[32] = {0x5b,0xf,0x6c,0x96,0x49,0x5f,0xd,0xb6,0x9b,0xb5,0x77,0x44,0xe8,0x21,0x8b,0x42,0x49,0x49,0xf2,0x4a,0x9f,0x82,0xe1,0xb,0xf4,0x70,0x75,0x85,0x62,0xc2,0x26,0x97};
    int i;
    for(i=0;i<20;i++)
    {
      my_cert[i] = 0x11;
    }
    
    MD5Context ctx;
    md5Init(&ctx);
    md5Update(&ctx,  my_cert, 20);
    md5Finalize(&ctx);
    uint8_t temp[32], check[64];
    for(i=0;i<16;i++)
    {
       temp[i] = 0;
    }
    for(i=0;i<16;i++)
    {
       temp[i+16] = ctx.digest[i];
    }
    uECC_n_operation_wp(my_private, temp, k, w);
    uECC_compute_public_key_wp(my_private, my_public);
    uECC_shared_secret_wp(Pa, temp, check);
    uint8_t x1[32],y1[32],x2[32],y2[32];
    for(i=0;i<32;i++)
    {
        x1[i] = check[i];
        y1[i] = check[i+32];
        x2[i] = CA_public[i];
        y2[i] = CA_public[i+32];
    }
    uECC_point_add_wp(x1,y1,x2,y2);
    
     ieee154e_getAsn(time);
    bytes0and1 = time[0]+256*time[1];
   openserial_printError(COMPONENT_COAPTEST,ERR_COAPTEST,(errorparameter_t)2,(errorparameter_t)bytes0and1);
     time_2 = bsp_timer_get_currentValue();
     //openserial_printInfo(COMPONENT_COAPTEST, ERR_COAPTEST,(errorparameter_t)my_public[0],(errorparameter_t)x1[0]);
     openserial_printError(COMPONENT_ECCM,ERR_ECC,(errorparameter_t)time_1,(errorparameter_t)time_2);
         
}*/

void nodejoin_mp_test_part2(void)
{
   uint16_t time_1,time_2;
  time_1 = bsp_timer_get_currentValue();
  /*uint8_t time[5];
  ieee154e_getAsn(time);
  uint16_t bytes0and1;
  bytes0and1 = time[0]+256*time[1];
   openserial_printError(COMPONENT_COAPTEST,ERR_COAPTEST,(errorparameter_t)3,(errorparameter_t)bytes0and1);*/
   
       uint8_t k[32] = {0xbf,0x20,0x35,0xbd,0x30,0xa7,0xe6,0x3a,0xbd,0xc6,0xb3,0xab,0x8,0x5c,0xe6,0x33,0xc2,0x24,0x5,0x7a, 0x11,0x22,0x33,0x44,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x1};
       uint8_t R_a[64];
       uint8_t my_address[16] = {0xbb,0xbb,0x00,0x00,0x00,0x00,0x00,0x00,0x14,0x15,0x92,0x05,0x01,0x01,0x00,0x1e};
       //compute public key
       uECC_compute_public_key_mp(k, R_a);
       uint8_t temp[uECC_BYTES+16];
       int i;
       for(i=0; i<uECC_BYTES; i++)
       {
         temp[i] = R_a[i];
       }
       for(i=uECC_BYTES; i<uECC_BYTES+16; i++)
       {
         temp[i] = my_address[i-uECC_BYTES];
       }
       MD5Context ctx;
       md5Init(&ctx);
       md5Update(&ctx, temp, uECC_BYTES+16);
       md5Finalize(&ctx);
       
       /*ieee154e_getAsn(time);
    bytes0and1 = time[0]+256*time[1];
   openserial_printError(COMPONENT_COAPTEST,ERR_COAPTEST,(errorparameter_t)4,(errorparameter_t)bytes0and1);*/
       time_2 = bsp_timer_get_currentValue();
     openserial_printError(COMPONENT_ECCM,ERR_ECC,(errorparameter_t)time_1,(errorparameter_t)time_2);
       openserial_printError(COMPONENT_ECCM,ERR_ECC,(errorparameter_t)R_a[0],(errorparameter_t)R_a[1]);
}

/*void nodejoin_wp_test_part2(void)
{
   uint16_t time_1,time_2;
  time_1 = bsp_timer_get_currentValue();
  
  uint8_t time[5];
  ieee154e_getAsn(time);
  uint16_t bytes0and1;
  bytes0and1 = time[0]+256*time[1];
   openserial_printError(COMPONENT_COAPTEST,ERR_COAPTEST,(errorparameter_t)3,(errorparameter_t)bytes0and1);
       uint8_t k[32] = {0xbf,0x20,0x35,0xbd,0x30,0xa7,0xe6,0x3a,0xbd,0xc6,0xb3,0xab,0x8,0x5c,0xe6,0x33,0xc2,0x24,0x5,0x7a, 0x11,0x22,0x33,0x44,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x1};
       uint8_t R_a[64];
       uint8_t my_address[16] = {0xbb,0xbb,0x00,0x00,0x00,0x00,0x00,0x00,0x14,0x15,0x92,0x05,0x01,0x01,0x00,0x1e};
       //compute public key
       uECC_compute_public_key_wp(k, R_a);
       uint8_t temp[uECC_BYTES+16];
       int i;
       for(i=0; i<uECC_BYTES; i++)
       {
         temp[i] = R_a[i];
       }
       for(i=uECC_BYTES; i<uECC_BYTES+16; i++)
       {
         temp[i] = my_address[i-uECC_BYTES];
       }
       MD5Context ctx;
       md5Init(&ctx);
       md5Update(&ctx, temp, uECC_BYTES+16);
       md5Finalize(&ctx);
       ieee154e_getAsn(time);
    bytes0and1 = time[0]+256*time[1];
   openserial_printError(COMPONENT_COAPTEST,ERR_COAPTEST,(errorparameter_t)4,(errorparameter_t)bytes0and1);
       time_2 = bsp_timer_get_currentValue();
     openserial_printError(COMPONENT_ECCM,ERR_ECC,(errorparameter_t)time_1,(errorparameter_t)time_2);
       //openserial_printError(COMPONENT_ECCM,ERR_ECC,(errorparameter_t)R_a[0],(errorparameter_t)R_a[1]);
}*/