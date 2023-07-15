#ifndef __KEYGEN_H
#define __KEYGEN_H

#include "opendefs.h"
#include "opentimers.h"
#include "windows_projective.h"

//=========================== define ==========================================


#define KEYGEN_PERIOD_MS 5000
#define KEYGEN_RUN_TIME 100
#define PROTOCOL_ID 0xcc
#define messeage_frag 0xff
#define messeage_check 0xfe
#define NODE_1 0x2
#define NODE_2 0x1e
#define NODE_3 0x5
#define NODE_4 0x8
#define NODE_5 0x6

//=========================== typedef =========================================

//=========================== variables =======================================



typedef struct
{
   opentimer_id_t       timerId;  
   uint16_t              period;
   uint8_t               my_id;
   bool                  state;
   uint8_t       my_da[uECC_BYTES];
   uint8_t       my_cert[uECC_BYTES];
   uint8_t       his_cert[uECC_BYTES];
   uint8_t       my_Pa[2*uECC_BYTES];
   uint8_t       his_Pa[2*uECC_BYTES];
   uint8_t       my_Qa[2*uECC_BYTES];
   uint8_t       his_Qa[2*uECC_BYTES];
   uint8_t       my_mic[20];
   uint8_t       his_mic[20];
   uint8_t       my_nonce[6];
   uint8_t       his_nonce[6];
   uint8_t       shared_key[2*uECC_BYTES];
   uint8_t       wait_distance;
   open_addr_t last_Neighbor;
} keygen_vars_t;


//=========================== prototypes ======================================

void keygen_init(void);
void keygen_receive(OpenQueueEntry_t *msg);


#endif