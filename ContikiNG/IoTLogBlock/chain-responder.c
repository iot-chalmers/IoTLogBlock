#include "contiki.h"
#include "random.h"
#include "net/ipv6/simple-udp.h"
#include "dev/rom-util.h"
#include "dev/sha256.h"
#include "dev/ecc-algorithm.h"
#include "dev/ecc-curve.h"
#include "sys/rtimer.h"
#include "sys/pt.h"
#include "sys/energest.h"
#include "sys/log.h"
#include <stdbool.h>


#define LOG_MODULE "Chain-Resp"
#define LOG_LEVEL LOG_LEVEL_DBG

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678
#define MAX_TXS 50
#define TX_INTERVAL (90 * CLOCK_SECOND)
#define REV(X) ((X << 24) | ((X & 0xff00) << 8) | ((X >> 8) & 0xff00) | (X >> 24))

#define RESOLVE_TIMEOUT (120 * CLOCK_SECOND)




static struct simple_udp_connection udp_conn;

static const char *const str_res[] = {
    "success",
    "invalid param",
    "NULL error",
    "resource in use",
    "DMA bus error"};



// ASW protocol :
// O -> R me1 = sigO{ Vo, Vr, T, text, Hash(NonceO)  }
// R -> O me2 = sig {me1, Hash(NonceR)}
// O -> R me3 = NonceO
// R -> O me4 = NonceR

typedef enum
{
  MSG_TYPE_HELLO,      // Init message ( discovery-braodcast)
  MSG_TYPE_READY,      // Init message Ready for exchagne (unicast)
  MSG_TYPE_M1,  // Starting the transcaction
  MSG_TYPE_M2,    // Respond accorgin to ASW protocol
  MSG_TYPE_M3,   // nonce of originator
  MSG_TYPE_M4,  // nonce of Responder
  MSG_TYPE_FOG,            // Connection with fog-edge discovery message
  MSG_TYPE_FORWARD // Forward records to the blockchain
} msg_type;
typedef enum
{
  STATUS_COMPLETE,
  STATUS_ABORT,
  STATUS_RESOLVE
} rec_status;

// ***** Helping Structures *****
typedef struct __attribute__((__packed__)) msg_header
{
  msg_type type;
  uint8_t data[];
} msg_header;

typedef struct __attribute__((__packed__)) msg_crypto
{
  // uint32_t msg_hash[8];     // hash of the message ->> to sing with ecc
  ec_point_t point_r;       // ecc - r (x coordinate)
  // uint32_t signature_o[24]; // ecc - Signature of originator
  // uint32_t signature_r[24];  // ecc - Signature of respond
  // short nonce_o; // nonce of originator
  // short nonce_r; // nonce of responder
} msg_crypto;


typedef struct __attribute__((__packed__)) msg_contex
{
  uint16_t originator_id;   // The id of node that stars the transaction
  uint16_t responder_id;    // The peer node of the trensaction
  uint16_t smart_contract_id;  // Trusted 3rd party (as part of) Asokan-Shoup-Waidner  protocol
  uint16_t record_id;        // the independant record
  uint32_t hash_nonce_o[8]; // nonce(Originator) for the Asokan-Shoup-Waidner protocol
} msg_contex;



//***** Main Messages *****

// message-1 of ASW protocol m1 + nonce of O
typedef struct __attribute__((__packed__)) msg_m1
{
  msg_type type;
  msg_contex context;
  ec_point_t point_r;    
  uint32_t signature_o[24]; // ecc - Signature of originator
} msg_m1;


//message-2 of ASW protocol contains the signature of m1 + nonce of R
typedef struct __attribute__((__packed__)) msg_m2
{
   msg_type type;
  // msg_transction me1;  // the orignal message
  uint32_t hash_nonce_r[8]; // Nonce(Responde) for the Asokan-Shoup-Waidner protocol
  uint32_t signature_r[24]; // signature of m1(message of origantator + hash of nonce_r) 
  // NOTE : in practice the responder just add the hash of nonce_r to orignal mesg

} msg_m2;

typedef struct __attribute__((__packed__)) msg_m3
{
  msg_type type;
  short nonce; // Nonce for the Asokan-Shoup-Waidner protocol
} msg_m3;

//message-3-4 of ASW contain the nonce
typedef struct __attribute__((__packed__)) msg_m4
{
  msg_type type;
  short nonce; // Nonce for the Asokan-Shoup-Waidner protocol
} msg_m4;

typedef struct __attribute__((__packed__)) msg_record
{
  msg_m1 m1;
  msg_m2 m2;
  short nonce_o;
  short nonce_r;
  rec_status status;
  u_int16_t rec_counter;
} msg_record;


// me2 is only for responder 
typedef struct __attribute__((__packed__)) me2
{
  uint32_t signature_o[24]; // signature of m1(message of origantator + hash of nonce_r)
  uint32_t hash_nonce_r[8];
} me2;


static rtimer_clock_t time;
uint16_t buffer_counter = 0;
static msg_record msg_buffer;
static msg_m1 msg_m1_buffer;
static uip_ipaddr_t dest_iot_node = {{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}};

static struct etimer resolve_period;
PROCESS(chain_server_process, "UDP server");
AUTOSTART_PROCESSES(&chain_server_process);
/*---------------------------------------------------------------------------*/
static short nonce;
static bool tx_free = true;

static void
udp_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen)
{
  // int i;
  msg_header *msg_rcv = (struct msg_header *)data;
  printf("MSg : %d\n", msg_rcv->type);
  int i;

  // msg_awp_respond reply_respond;
  msg_m4 reply_nonce;
  msg_header reply_hello;
  LOG_INFO("Received  from ");
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_("\n");

  switch (msg_rcv->type)
  {
  //hello message is the broadcast message for neighbor discovery
  case MSG_TYPE_HELLO:
  {
    // LOG_INFO("Received from ");
    // LOG_INFO_6ADDR(sender_addr);
    // LOG_INFO_("\n");
    memcpy(&dest_iot_node, sender_addr, sizeof(uip_ipaddr_t));
    // LOG_INFO_6ADDR(&dest_iot_node);
    //   LOG_INFO_("\n");

    // a new node wants to make Transcaction
    // check if ongoin transaction exists
    // memcpy(&dest_iot_node,  sender_addr, sizeof(uip_ipaddr_t));
    //new transction , save ip of other node
    // A node replies to hello with an EXCHANGE to indicate that is ready to accept transactions
    reply_hello.type = MSG_TYPE_READY;
    simple_udp_sendto(&udp_conn, &reply_hello, sizeof(struct msg_header), &dest_iot_node);
    // printf("rcv: MSG_TYPE_EXCHANGE  and send function: %d \n");
  }
  break;
  // Oginate message has signature of m1 + nonce of R
  case MSG_TYPE_M1:
  {
    //Verification function need to called as thread
    //he pass the handle to main process using event msg
    if (tx_free == true)
    {
      
      
      // printf("\n******\n");
      // struct msg_contex *strucPtr2 = &rcv_m1.context;
      // unsigned char *charPtr2 = (unsigned char *)strucPtr2;
      // for (i = 0; i < sizeof(struct msg_contex); i++)
      //   printf("%02x", charPtr2 [i]);


      memcpy(&msg_buffer.m1, msg_rcv, sizeof(msg_m1));
      memcpy(&msg_m1_buffer, msg_rcv, sizeof(msg_m1));

printf("\n get m1\n");
//       struct msg_contex *strucPtr2 = &msg_m1_buffer.context;
//       unsigned char *charPtr2 = (unsigned char *)strucPtr2;
//       for (i = 0; i < sizeof(struct msg_contex); i++)
//         printf("%02x", charP tr2 [i]);


      process_post(&chain_server_process, PROCESS_EVENT_MSG, (process_data_t)&msg_m1_buffer);
      // tx_free = false;
      // memcpy(&dest_iot_node, sender_addr, sizeof(uip_ipaddr_t));
    }
  }
  break;

  case MSG_TYPE_M3:
  {
    // printf("nonce of origin%d\n", ((msg_awp_nonce *)msg_rcv)->nonce);
    etimer_stop(&resolve_period);
    crypto_init();
    sha256_state_t state;
    uint8_t sha256[32];
    uint32_t sha256_digest[8];
    int len = sizeof(short);
    int ret;
    ret = sha256_init(&state);
    ret = sha256_process(&state, &((msg_m3 *)msg_rcv)->nonce, len);
    ret = sha256_done(&state, sha256);
    printf("sha256_process(): %s\n", str_res[ret]);
    
    crypto_disable();

    uint32_t *ptr = (uint32_t *)&sha256;
    int j = 7;
    for (i = 0; i < 8; i++)
    {
      sha256_digest[i] = REV(ptr[j]);
      printf("%08lx", REV(ptr[j]));
      j--;
    }

    // printf("sha256_done(): %s \n", str_res[ret]);
    //to_send.m_crypto.hash_256 = sha256;
    if (rom_util_memcmp(sha256_digest, msg_buffer.m1.context.hash_nonce_o, sizeof(sha256)))
    {
      printf("nonce not match");
    }
    else
    {
      printf("NonceO hash OK\n");
    }
    puts("----------------");
    reply_nonce.type = MSG_TYPE_M4;
    reply_nonce.nonce = nonce;
    simple_udp_sendto(&udp_conn, &reply_nonce, sizeof(struct msg_m4), sender_addr);
    tx_free = true;
  }
  break;

  default: /* Optional */
    printf("Undifined msg type\n");
  }

 
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(chain_server_process, ev, data)
{
  static ecc_dsa_verify_state_t verify_state = {
      .process = &chain_server_process,
      .curve_info = &nist_p_256,
      .public.x = {0x5fa58f52, 0xe47cfbf2, 0x300c28c5, 0x6375ba10,
                   0x62684e91, 0xda0a9a8f, 0xf9f2ed29, 0x36dfe2c6},
      .public.y = {0xc772f829, 0x4fabc36f, 0x09daed0b, 0xe93f9872,
                   0x35a7cfab, 0x5a3c7869, 0xde1ab878, 0x71a0d4fc},
  };

  static ecc_dsa_sign_state_t sign_state = {
      .process = &chain_server_process,
      .curve_info = &nist_p_256,
      .secret = {0x94A949FA, 0x401455A1, 0xAD7294CA, 0x896A33BB,
                 0x7A80E714, 0x4321435B, 0x51247A14, 0x41C1CB6B},
      .k_e = {0x1D1E1F20, 0x191A1B1C, 0x15161718, 0x11121314,
              0x0D0E0F10, 0x090A0B0C, 0x05060708, 0x01020304},
  };

  static sha256_state_t state;
  static uint8_t sha256_digest[32];
  static uint8_t ret;
  static size_t len;
  static msg_m2 reply_m2;
  static msg_m1 rcv_m1;

  PROCESS_BEGIN();

  /* Initialize DAG root */
  // NETSTACK_ROUTING.root_start();
  // printf("\nset up udp \n");
  /* Initialize UDP connection */
  simple_udp_register(&udp_conn, UDP_SERVER_PORT, NULL, UDP_CLIENT_PORT, udp_rx_callback);
  // etimer_set(&tx_period, TX_INTERVAL);
  // u_int8_t start = 0;
  // simple_udp_sendto(&udp_conn, &start, sizeof( u_int8_t), &dest_iot_node);
  while (1)
  {
    PROCESS_WAIT_EVENT();
    // printf("evetnt \n");
    if (ev == PROCESS_EVENT_MSG)
    {
      printf("msg handler");
      reply_m2.type = MSG_TYPE_M2;
      etimer_set(&resolve_period, RESOLVE_TIMEOUT);
      // msg_rcv = data;
      memcpy(&rcv_m1, data, sizeof(msg_m1));
      // IMPORTANT!! Initializing cryptoprocessor before use
      crypto_init();
      pka_init();

      len = sizeof(struct msg_contex);
      ret = sha256_init(&state);
      ret = sha256_process(&state, &rcv_m1.context, len);
      ret = sha256_done(&state, sha256_digest);
     
      uint32_t *ptr = (uint32_t *)&sha256_digest;
      int j = 7;
      int i = 0;
      for (i = 0; i < 8; i++)
      {
        verify_state.hash[i] = REV(ptr[j]);
        j--;
      }

      memcpy(verify_state.signature_r, &rcv_m1.point_r, sizeof(ec_point_t));
      memcpy(verify_state.signature_s, &rcv_m1.signature_o, sizeof(uint32_t) * 8);

      time = RTIMER_NOW();
      PT_SPAWN(&(chain_server_process.pt), &(verify_state.pt), ecc_dsa_verify(&verify_state));
      time = RTIMER_NOW() - time;
      printf("verification  time: , %lu ms\n",
             (uint32_t)((uint64_t)time * 1000 / RTIMER_SECOND));

      if (verify_state.result)
      {
        puts("signature verification failed");
      }
      else
      {
        puts("signature verification OK");
      }

      // form the M2 to send to the originator
      me2 data_for_sign; 
      nonce = random_rand();
      len = sizeof(nonce);
      printf("\n");
      // printf("nonce of reposnd: %d\n", nonce);

      ret = sha256_init(&state);
      // printf("sha256_init(): %s \n", str_res[ret]);
      ret = sha256_process(&state, &nonce, len);
      ret = sha256_done(&state, sha256_digest);
      printf("sha256_process(): %s\n", str_res[ret]);
      // uint32_t *ptr = (uint32_t *)&sha256; //cast the 8bit pointer to an 32bit pointer
      //flip the hash bit (order of uint32_t)
      // the first 8 bytes will be used, the others are padding of 0s
      ptr = (uint32_t *)&sha256_digest;
      j = 7;
      for (i = 0; i < 8; i++)
      {
        reply_m2.hash_nonce_r[i] = REV(ptr[j]);
        // printf("%08lx",reply_m2.hash_nonce_r[i]);
        msg_buffer.m2.hash_nonce_r[i] = REV(reply_m2.hash_nonce_r[i]);
        data_for_sign.hash_nonce_r[i] = REV(reply_m2.hash_nonce_r[i]);
        j--;
      }
      // Data for sign = signature of Originator + Hash of Nonce
      memcpy(&data_for_sign.signature_o, &rcv_m1.signature_o, sizeof(uint32_t) * 24 );
     
    //  printf("\n++++\n");
    //  struct me2 *strucPtr = &data_for_sign;
    //   unsigned char *charPtr = (unsigned char *)strucPtr;
      // printf("structure size : %d bytes\n", sizeof(struct msg_transction));
      // // printf("\n");//hex:
      // for (i = 0; i < sizeof(struct me2); i++)
      //   printf("%02x", charPtr[i]);

      // printf("++++\n");
      // printf("\n---\n");

      len = sizeof(struct me2);
      ret = sha256_init(&state); 
      ret = sha256_process(&state, &data_for_sign, len);
      ret = sha256_done(&state, sha256_digest);
      ptr = (uint32_t *)&sha256_digest;
      j = 7;
      for (i = 0; i < 8; i++)
      {
        sign_state.hash[i] = REV(ptr[j]);
        // printf("%08lx", sign_state.hash[i]);
        j--;
      }

      // printf("\n---\n");
      time = RTIMER_NOW();
      PT_SPAWN(&(chain_server_process.pt), &(sign_state.pt), ecc_dsa_sign(&sign_state));
      time = RTIMER_NOW() - time;
      printf("sing of responder,  time: , %lu ms\n",
              (uint32_t)((uint64_t)time * 1000 / RTIMER_SECOND));

      memcpy(reply_m2.signature_r, sign_state.signature_s, sizeof(uint32_t) * 8);
      // signature
      // for (i = 7; i >= 0; i--)
      // {
      //   printf("%08lx",  sign_state.signature_s[i]);
      // }
      // printf("\n");
      // printf("\n---\n");
      i = simple_udp_sendto(&udp_conn, &reply_m2, sizeof(struct msg_m2), &dest_iot_node);
      printf("send msg: %d\n", i);

      crypto_disable();
      pka_disable();
    }
    else if (etimer_expired(&resolve_period))
    {
      //clear transaction
      //send an resolve ->
      printf("RESOLVE time expired\n");
      // tx_free = true;
      // etimer_set(&resolve_period, TX_INTERVAL);
    }
  }
  PROCESS_END();
}

 /* 
  // //Initializing cryptoprocessor
  // crypto_init();
  // //"Initializing pka..."
  // pka_init();
  
  // // ret = sha256_init(&state);
  // //PROCESS_PAUSE();
  // //Check if the initializatio was successfull
  // // printf("sha256_init(): %s \n", str_res[ret]);

  // // ret = sha256_process(&state, &rcv_msg->body, len);
  // //PROCESS_PAUSE();

  // // printf("sha256_process(): %s\n", str_res[ret]);

  // // ret = sha256_done(&state, sha256);
  // // //PROCESS_PAUSE();

  // // printf("sha256_done(): %s \n", str_res[ret]);
  // //to_send.m_crypto.hash_256 = sha256; 

  // // printf("sha256 digest: \n");
  // // int i ;
  // // for (i = 0 ; i < 32 ; i++ ){
  // //   printf("%02x",sha256[i] );
  // // }
  // // printf("\n hash of rcv msg:");
  // // for (i = 0 ; i < 8 ; i++ ){
  // //   printf("%lx",rcv_msg->m_crypto.hash_256[i] );
  // // }
  // // printf("\n signature of rcv msg:");
  // // for (i = 0 ; i < 8 ; i++ ){
  // //   printf("%lx",rcv_msg->m_crypto.signature_s[i] );
  // // }

  // // ecc_dsa_verify_state_t verify_state = {
  // //   .process     = &udp_server_process,
  // //   .curve_info  = &nist_p_256,
  // // };
  // // uint32_t public_x[8] = { 0x5fa58f52, 0xe47cfbf2, 0x300c28c5, 0x6375ba10,
  // //                                 0x62684e91, 0xda0a9a8f, 0xf9f2ed29, 0x36dfe2c6 };
  // // uint32_t public_y[8] = { 0xc772f829, 0x4fabc36f, 0x09daed0b, 0xe93f9872,
  // //                                 0x35a7cfab, 0x5a3c7869, 0xde1ab878, 0x71a0d4fc };

  // // memcpy(verify_state.public.x, public_x, sizeof(public_x));
  // // memcpy(verify_state.public.y, public_y, sizeof(public_y));
  // // memcpy(verify_state.signature_r,&rcv_msg->m_crypto.point_r, sizeof(rcv_msg->m_crypto.point_r));
  // // memcpy(verify_state.signature_s, &rcv_msg->m_crypto.signature_s, sizeof(rcv_msg->m_crypto.signature_s) );
  // // memcpy(verify_state.hash,&rcv_msg->m_crypto.hash_256, sizeof(rcv_msg->m_crypto.hash_256) );
  
  // ret = ecc_dsa_verify(&verify_state);
  // //PROCESS_PAUSE();
  // // PT_SPAWN(&(udp_server_process.pt), &(verify_state.pt), ecc_dsa_verify(&verify_state));
  // printf("\n-----\n");
  //   if(verify_state.result) {
  //     puts("signature verification failed");
  //   } else {
  //     puts("signature verification OK");
  //   }
  //     printf("\n--------\n");
  //   puts("-----------------------------------------\n"
  //       "Disabling cryptoprocessor...");
  //   crypto_disable();

  //   puts("-----------------------------------------\n"
  //       "Disabling pka...");
  //   pka_disable();

  //   puts("Done!"); 
  */