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
#include "Offchain-message.h"

// #define CONSTANT_CONNECTIVITY 
#define MEASURE_ENERGY

#define LOG_MODULE "Chain-Orig"
#define LOG_LEVEL LOG_LEVEL_DBG
#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678
#define MAX_TXS 30

//REV reversve the byte order 
#define REV(X) ((X << 24) | ((X & 0xff00) << 8) | ((X >> 8) & 0xff00) | (X >> 24))
#define GENERATION_INTERVAL (10 * CLOCK_SECOND)
#define START_INTERVAL (0.001 * CLOCK_SECOND)
#define TX_INTERVAL (90 * CLOCK_SECOND)
#define EDGE_CONNECTION (30 * CLOCK_SECOND)
#define RESOLVE_TIMEOUT (120 * CLOCK_SECOND)
#define ABORD_TIMEOUT (120 * CLOCK_SECOND)
#define NODE_ID 1


static int memory_max = 0;
static uint16_t droped_rec = 0;
static const uint16_t node_id = NODE_ID;
static bool tx_free = true;
static u_int32_t record_counter = 0;
static struct simple_udp_connection udp_conn;

#ifdef MEASURE_ENERGY
static unsigned long
to_seconds(uint64_t time)
{
  return (unsigned long)(time / ENERGEST_SECOND);
}
#endif


static uint32_t buffer_counter = 0;
static msg_record  buffer[MAX_TXS];
static msg_header msg_buffer;
static msg_record complete_rec;
static uip_ipaddr_t dest_iot_node = {{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}};

/*---------------------------------------------------------------------------*/
PROCESS(chain_client_process, "Chain client");
AUTOSTART_PROCESSES(&chain_client_process);
/*---------------------------------------------------------------------------*/

static void
udp_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen)
{
  msg_header *msg_rcv = (struct msg_header *)data;
  // printf("MSg recvd: %d\n", msg_rcv->type);

  switch (msg_rcv->type)
  {
  // An exchange message means the other end is ready for Transcaction
  case MSG_TYPE_READY:
  {
    // check if there is ongoing transcation
    // only one transction can be made each sesssion
    if (tx_free == true)
    {
      // new transction , save ip of other node
      memcpy(&dest_iot_node, sender_addr, sizeof(uip_ipaddr_t));
      memcpy(&msg_buffer, msg_rcv, sizeof(msg_header));
      // A P-thread needed to  sing transctions
      // threads can spawn only by processed
      // thus we send a msg_event to main process to handle it
      process_post(&chain_client_process, PROCESS_EVENT_MSG, (process_data_t)&msg_buffer);
      tx_free = false;
    }
    // in case ongoing transction , do nothing , a timer handles failure
  }
  break;

  //the Responder send the m2
  case MSG_TYPE_M2:
  {

    // msg_m2 * r_m2 = (struct msg_m2 *)data;

    
    // memcpy(&complete_rec.body.hash_nonce_r, r_hash->body.hash_nonce_r, sizeof(uint32_t) * 8);
    // memcpy(&complete_rec.body.crypto.signature_r ,r_hash->body.signature_r, sizeof(uint32_t) * 24);
    memcpy(&msg_buffer, msg_rcv, sizeof(msg_rcv));
    process_post(&chain_client_process, PROCESS_EVENT_MSG, (process_data_t)&msg_buffer);
  }
  break;

  case MSG_TYPE_M4:
  {

    memcpy(&msg_buffer, msg_rcv, sizeof(msg_rcv));
    process_post(&chain_client_process, PROCESS_EVENT_MSG, (process_data_t)&msg_buffer);

    // printf("MSG_TYPE_NONCE_RPD, type: %d\n", ((msg_chain *)msg_rcv)->type);
    // // need to send the nonce O
    // for (i = 0; i < 7; i++)
    //   printf("nonce1: %ld \n", ((msg_awp_resp *)msg_rcv)->hash_nonce_r[i]);
  }
  break;

  default: //Optional
  {
    printf("Undifined msg type\n");
  }
  }
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(chain_client_process, ev, data)
{
  static struct etimer periodic_hello, edge_connection;//abord_period, resolve_period, ;
  static unsigned count;
  // static int i,j;
  static msg_m1 reply_m1;
  static msg_m3 reply_m3;
  static short nonce;

  static sha256_state_t sha256_state;
  static uint8_t sha256_digest[32];
  static uint8_t ret;
  static uint32_t len;

  static ecc_dsa_sign_state_t sign_state = {
      .process = &chain_client_process,
      .curve_info = &nist_p_256,
      .secret = {0x94A949FA, 0x401455A1, 0xAD7294CA, 0x896A33BB,
                 0x7A80E714, 0x4321435B, 0x51247A14, 0x41C1CB6B},
      .k_e = {0x1D1E1F20, 0x191A1B1C, 0x15161718, 0x11121314,
              0x0D0E0F10, 0x090A0B0C, 0x05060708, 0x01020304},
  };
  static rtimer_clock_t time;
  static rtimer_clock_t total_time;

  // node ready for transaction in the start
  tx_free = true;

  PROCESS_BEGIN();
  /* Initialize UDP connection */
  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL, UDP_SERVER_PORT, udp_rx_callback);
  etimer_set(&periodic_hello, START_INTERVAL);
  etimer_set(&edge_connection, EDGE_CONNECTION);

  while (1)
  {
    // printf ("size of m1 = %d\n",sizeof(struct msg_m1));
    // printf ("size of record= %d\n",sizeof(struct msg_record));


    PROCESS_WAIT_EVENT(); //_UNTIL((ev == PROCESS_EVENT_TIMER) || (ev == PROCESS_EVENT_MSG)); //etimer_expired(&periodic_timer)
    // Update all energest times.
  #ifdef MEASURE_ENERGY 
    energest_flush();

    printf("\nEnergest:\n");
    printf(" CPU          %4lus LPM      %4lus DEEP LPM %4lus  Total time %lus\n",
           to_seconds(energest_type_time(ENERGEST_TYPE_CPU)),
           to_seconds(energest_type_time(ENERGEST_TYPE_LPM)),
           to_seconds(energest_type_time(ENERGEST_TYPE_DEEP_LPM)),
           to_seconds(ENERGEST_GET_TOTAL_TIME()));
    printf(" Radio LISTEN %4lus TRANSMIT %4lus OFF      %4lus\n",
           to_seconds(energest_type_time(ENERGEST_TYPE_LISTEN)),
           to_seconds(energest_type_time(ENERGEST_TYPE_TRANSMIT)),
           to_seconds(ENERGEST_GET_TOTAL_TIME() - energest_type_time(ENERGEST_TYPE_TRANSMIT) - energest_type_time(ENERGEST_TYPE_LISTEN)));
#endif

    // The udp callback send an event for messages related to AWP protocol:
    // This is because the cyrpto funcations need to handled as a thread

    // printf(" memory_max : %d\n",memory_max);
    if (ev == PROCESS_EVENT_MSG)
    {
      //select through the type of msg
      msg_header *msg_rcv = (struct msg_header *)data;
      // nodes said hello -> ready for exchange
      if (msg_rcv->type == MSG_TYPE_READY)
      {
        record_counter++;
        printf("<rec_timestamp>%ld\n",record_counter);
        //start measure the time for protocol to complete
        total_time = RTIMER_NOW();
        //start a transation process
        // etimer_set(&abord_period, ABORD_TIMEOUT);

        //IMPORTANT! neet to init crypto coprocessor before use
        crypto_init();
        pka_init();
        uint32_t *ptr = (uint32_t *)&sha256_digest;

        reply_m1.type = MSG_TYPE_M1;
        reply_m1.context.originator_id = 1;
        reply_m1.context.responder_id = 2;
        reply_m1.context.smart_contract_id =3;
        reply_m1.context.record_id = 4;
        nonce = random_rand();
        len = sizeof(short);
        // printf("Nonce of originator :%d\n",nonce);

        // printf("structure size : %du bytes\n", sizeof(struct msg_body));
        // for (i = 0; i < sizeof(struct msg_body); i++)
        //   printf("%02x", charPtr[i]);

        // time = RTIMER_NOW();
        //Check if the initialization was successfull
        ret = sha256_init(&sha256_state);
        // printf("sha256_init(): %s \n", str_res[ret]);
        ret = sha256_process(&sha256_state, &nonce, len);
        // printf("sha256_process(): %s\n", str_res[ret]);
        ret = sha256_done(&sha256_state, sha256_digest);

        // time = RTIMER_NOW() - time;
        // printf("sha256 - nonce time: , %lu ms\n",
        //        (uint32_t)((uint64_t)time * 10000 / RTIMER_SECOND));

        // printf("\nHash of nonce :\n");
        ptr = (uint32_t *)&sha256_digest;
         int i;
        int j = 7;
        for (i = 0; i < 8; i++)
        {
          reply_m1.context.hash_nonce_o[i] = REV(ptr[j]);;
          // printf("%08lx", reply_m1.context.hash_nonce_o[i] );
          j--;
        }
        // printf("\n.\n");


        // 
        len = sizeof(struct msg_contex);
        // time = RTIMER_NOW();
        ret = sha256_init(&sha256_state);
        // printf("sha256_init(): %s \n", str_res[ret]);
        ret = sha256_process(&sha256_state, &reply_m1.context, len);
        printf("sha256_process(): %d\n", ret);
        // ret = sha256_done(&sha256_state, &sha256_digest[0]);
        ret = sha256_done(&sha256_state, sha256_digest);

        // time = RTIMER_NOW() - time;
        // printf("sha256 - reply.body.me1 ,  time: , %lu ms\n",
        //        (uint32_t)((uint64_t)time * 1000 / RTIMER_SECOND));

        // struct msg_transction *strucPtr = &reply.body.me1;
        // unsigned char *charPtr = (unsigned char *)strucPtr;
        // printf("structure size : %d bytes\n", sizeof(struct msg_transction));
        // printf("hex:\n");
        // for (i = 0; i < sizeof(struct msg_transction); i++)
        //   printf("%02x", charPtr[i]);

        // printf("\nhash of signature: ");
        // printf("\n");
        // printf("hash(): %s \n", str_res[ret]);
        // This is how should print the hash to test from other program
        // in contiki the hash is used in revered bit-order
        
        ptr = (uint32_t *)&sha256_digest;
        j=7;
        for (i = 0; i < 8; i++)
        {
          sign_state.hash[i] = REV(ptr[j]);
          // printf("%08lx", REV(ptr[i]));
          j--;
        }

        // printf("\n---\n");
        time = RTIMER_NOW();
        PT_SPAWN(&(chain_client_process.pt), &(sign_state.pt), ecc_dsa_sign(&sign_state));
        time = RTIMER_NOW() - time;
        printf("sing of origin msg,  time: , %lu ms\n",
               (uint32_t)((uint64_t)time * 1000 / RTIMER_SECOND));

        reply_m1.point_r = sign_state.point_r;
        memcpy(reply_m1.signature_o, sign_state.signature_s, sizeof(uint32_t) * 24);
        memcpy(&complete_rec, &reply_m1, sizeof(msg_m1));

        //copy the reply message to global  buffer complete_tx
      
        complete_rec.nonce_o = nonce;

        crypto_disable();
        pka_disable();
        simple_udp_sendto(&udp_conn, &reply_m1, sizeof(struct msg_m1), &dest_iot_node);
       

      }
      else if (msg_rcv->type == MSG_TYPE_M2)
      {
        //responder send m2 
        // printf("got m2\n");
        //stop abort timeout
        // etimer_stop(&abord_period);
        //start resolving timeout
        // etimer_set(&resolve_period, RESOLVE_TIMEOUT);
        memcpy(&complete_rec.m2, msg_rcv, sizeof(msg_m2) );
        reply_m3.type = MSG_TYPE_M3;
        reply_m3.nonce = nonce;
        simple_udp_sendto(&udp_conn, &reply_m3, sizeof(struct msg_m3), &dest_iot_node);
      }
      else if (msg_rcv->type == MSG_TYPE_M4)
      {
        // printf("nonce of respond:%d\n", ((msg_m4 *)msg_rcv)->nonce);

        crypto_init();
        sha256_state_t state;
        uint8_t sha256[32];
        uint32_t sha256_digest[8];
        int len = sizeof(short);
        ret = sha256_init(&state);
        ret = sha256_process(&state, &((msg_m4 *)msg_rcv)->nonce, len);
        ret = sha256_done(&state, sha256);
        // printf("sha256_process(): %s\n", str_res[ret]);
        crypto_disable();
        uint32_t *ptr = (uint32_t *)&sha256;
        int i;
        int j = 7;
        for (i = 0; i < 8; i++)
        {
          sha256_digest[i] = REV(ptr[j]);
          // printf("%08lx", REV(ptr[j]));
          j--;
        }

        if ( rom_util_memcmp(sha256_digest, &complete_rec.nonce_r, sizeof(sha256)) )
        {
          // printf("NonceR not match");
        }
        else
        {
          // printf("NonceR hash OK\n");
        }
        puts("----------------");

        // printf("Protocol done! tx Counter: %ld\n", record_counter);
        
        total_time = RTIMER_NOW() - total_time;
        printf("procol overall time: , %lu ms\n",
               (uint32_t)((uint64_t)total_time * 1000 / RTIMER_SECOND));
        tx_free = true;
        complete_rec.nonce_r = ((msg_m4 *)msg_rcv)->nonce;
        complete_rec.status = STATUS_COMPLETE;
        complete_rec.rec_counter = record_counter;
        if(buffer_counter < MAX_TXS){
          buffer[buffer_counter] = complete_rec; 
          buffer_counter++;
          printf("buffer counter : %ld\n",buffer_counter);
        }
        else{
          droped_rec++;
          printf("Record Droped :%d \n",droped_rec);

        }
        if(buffer_counter > memory_max){
          memory_max = buffer_counter;
          //  printf(" memory_max : %d\n",memory_max);
        }
        #ifdef CONSTANT_CONNECTIVITY
          printf("<transcation>\n");
          printf("%d\n",complete_rec.rec_counter);
          printf("%d\n",node_id);
          struct msg_record *strucPtr = &complete_rec;
          unsigned char *charPtr = (unsigned char *)strucPtr;
          for (i = 0; i < sizeof(struct msg_record); i++){
            printf("%02x", charPtr[i]);
          }
          printf("\n");
          //hex hash of nonce of respond
          uint32_t * hashPtr = complete_rec.m2.hash_nonce_r;
          charPtr = (unsigned char *)hashPtr;
          // printf("structure size : %d bytes\n", sizeof(struct msg_transction));
          // printf("\n");//hex:
          for (i = 0; i < sizeof(uint32_t) * 8; i++)
            printf("%02x", charPtr[i]);

          printf("\n");

          // signature
          for (i = 7; i >= 0; i--)
          {
            printf("%08lx", complete_rec.m1.signature_o[i]);
          }
          printf("\n");
          // signature
          for (i = 7; i >= 0; i--)
          {
            printf("%08lx", complete_rec.m2.signature_r[i]);
          }
          printf("\n");
          //Nonce of Origin
          printf("%d", complete_rec.nonce_o);
          printf("\n");
          //Nonce of Responder
          printf("%d", complete_rec.nonce_r);
          printf("\n");
          printf("</transcation>\n");
        #endif
      }
    }
    else if (ev == PROCESS_EVENT_TIMER)
    {
      if (etimer_expired(&periodic_hello))
      {

        msg_header to_send;
        to_send.type = MSG_TYPE_HELLO;
        printf("\nSending request %u ", count);
        printf("\n");
        /* Set the number of transmissions to use for this packet -
         this can be used to create more reliable transmissions or
         less reliable than the default. Works end-to-end if
         UIP_CONF_TAG_TC_WITH_VARIABLE_RETRANSMISSIONS is set to 1.
       */
        // uipbuf_set_attr(UIPBUF_ATTR_MAX_MAC_TRANSMISSIONS, 1 + count % 5);
        simple_udp_sendto(&udp_conn, &to_send, sizeof(struct msg_header), &dest_iot_node);
        count++;
        /* Add some jitter */
        etimer_set(&periodic_hello, GENERATION_INTERVAL - CLOCK_SECOND + (random_rand() % (2 * CLOCK_SECOND)));
      }
      if (etimer_expired(&edge_connection) )
      {
        printf("edge periodic connection\n");
        etimer_set(&edge_connection, EDGE_CONNECTION);
        
         if (buffer_counter > 0 ){
            #ifndef CONSTANT_CONNECTIVITY
            int transmit_record;
            for (transmit_record = 0; transmit_record < buffer_counter;transmit_record++)
            {  //buffer[buffer_counter] = complete_rec; 
              
              printf("<transcation>\n");
              printf("%d\n",buffer[transmit_record].rec_counter);
              printf("%d\n",node_id);
              struct msg_record *strucPtr = &buffer[transmit_record];
              unsigned char *charPtr = (unsigned char *)strucPtr;
              int i;
              for (i = 0; i < sizeof(struct msg_record); i++){
                printf("%02x", charPtr[i]);
              }
              printf("\n");
              //hex hash of nonce of respond
              uint32_t * hashPtr = buffer[transmit_record].m2.hash_nonce_r;
              charPtr = (unsigned char *)hashPtr;
              // printf("structure size : %d bytes\n", sizeof(struct msg_transction));
              // printf("\n");//hex:
              for (i = 0; i < sizeof(uint32_t) * 8; i++)
                printf("%02x", charPtr[i]);

              printf("\n");

              // signature
              for (i = 7; i >= 0; i--)
              {
                printf("%08lx", buffer[transmit_record].m1.signature_o[i]);
              }
              printf("\n");
              // signature
              for (i = 7; i >= 0; i--)
              {
                printf("%08lx", buffer[transmit_record].m2.signature_r[i]);
              }
              printf("\n");
              //Nonce of Origin
              printf("%d", buffer[transmit_record].nonce_o);
              printf("\n");
              //Nonce of Responder
              printf("%d", buffer[transmit_record].nonce_r);
              printf("\n");
              printf("</transcation>\n");
            
        
            

            }
            #endif
            buffer_counter=0;
           
         }
      }



      // if (etimer_expired(&abord_period))
      // {
      //   // sing protol is incomplete
      //   printf("ABORD timer expired \n");
      //   //clear transaction
      //   //check flag - > abord the protocol
      //   // complete_rec.status = STATUS_ABORT;
      //   // buffer[buffer_counter] = complete_rec; 
      //   // buffer_counter++;
      //   tx_free = true;
      // }
      // if (etimer_expired(&resolve_period))
      // {
      //   // sing protol is incomplete
      //   printf("RESOLVE timer expired \n");
      //   //clear transaction
      //   //check flag - > abord the protocol
      //   // complete_rec.status = STATUS_RESOLVE;
      //   // buffer[buffer_counter] = complete_rec; 
      //   // buffer_counter++;
      //   tx_free = true;
      // }
    }
  }

  PROCESS_END();
}
/*

  // printf("sha256_init(): %s \n", str_res[ret]);
  // ret = sha256_process(&state, &to_send.body, len);

  // ret = sha256_done(&state, sha256);

  // printf("sha256_done(): %s \n", str_res[ret]);

  // printf("\n unfliped h:");
  // printf("\n.hash:");
  // for (i = 0; i < 32; i++)
  // {
  //   printf("%02x", sha256[i]);
  // }
  // printf("\n");

  // uint32_t *ptr = (uint32_t *)&sha256; //cast the 8bit pointer to an 32bit pointer
  //flip the hash bit (order of uint32_t)
  //the first 8 bytes will be used, the others are padding of 0s
  // int j = 7;
  // for (i = 0; i < 8; i++)
  // {
  //   to_send.crypto.msg_hash[i] = REV(ptr[j]);
  //   j--;
  // }

  // for (i = 0; i < 8; i++)
  // {
  //   sign_state.hash[i] = sha256[i];
  // }

  // PT_SPAWN(&(chain_client_process.pt), &(sign_state.pt), ecc_dsa_sign(&sign_state));
  // // printf("\n ecc_dsa_sign() %s \n",str_res[sign_state2.result]);
  // to_send.crypto.point_r = sign_state.point_r;
  // memcpy(to_send.crypto.signature_s, sign_state.signature_s, sizeof(sign_state.signature_s));

  // printf("signature\n");
  // printf("h:");
  // for (i = 0; i < 8; i++)
  // {
  //   printf("%08lx", sign_state.hash[i]);
  // }
  // printf("\nr:");
  // for (i = 7; i >= 0; i--)
  // {
  //   printf("%08lx", sign_state.point_r.x[i]);
  // }
  // printf("\ns:");
  // for (i = 7; i >= 0; i--)
  // {
  //   printf("%08lx", sign_state.signature_s[i]);
  // }
  // printf("\n");
  // printf("/signature\n");

  // crypto_disable();
  // pka_disable();


    // printf("%02x", reply.type);
          //  printf("\n");
          // printf("%04x", reply.body.me1.originator_id);
          // printf("\n");
          // printf("%04x", reply.body.me1.responder_id);
          // // printf("\n");
          // printf("%04x", reply.body.me1.smart_contract);
          // // printf("\n");
          // printf("%04x", reply.body.me1.cargo_id);
          // // printf("\n");
          // for(i=0;i<8;i++)
          // printf("%08lx", reply.body.me1.hash_nonce_o[i]);
          // // printf("\n");

          // for(i=0;i<8;i++)
          // printf("%08lx", reply.body.crypto.msg_hash[i]);
          // // printf("point x \n");
          // for(i=0;i<12;i++)
          // printf("%08lx", reply.body.crypto.point_r.x[i]);
          // // printf("point y \n");
          // for(i=0;i<12;i++)
          // printf("%08lx", reply.body.crypto.point_r.y[i]);
          // // printf(" sign \n");
          // for(i=0;i<24;i++)
          // printf("%08lx", reply.body.crypto.signature_s[i]);
          // // printf("\n");
          // printf("%04x", reply.body.crypto.nonce_o);
          // // printf("\n");
          // printf("%04x", reply.body.crypto.nonce_r);

              //  puts("----------------");
          //         uint32_t *ptr = (uint32_t *)&sha256;
          //         int j = 7;
          //         for (i = 0; i < 8; i++)
          //         {
          //           sha256_digest[i] = REV(ptr[j]);
          //           printf("%08lx", REV(ptr[j]));
          //           j--;
          //         } puts("----------------");

          // printf("sha256_done(): %s \n", str_res[ret]);
          //to_send.m_crypto.hash_256 = sha256;

                  // printf("\n ecc_dsa_sign() %s \n", str_res[sign_state.result]);
          // printf("signature\n");
          // printf("h:");
          // for (i = 0; i < 8; i++)
          // {
          //   printf("%08lx", sign_state.hash[i]);
          // }
          // printf("\nr:");
          // for (i = 7; i >= 0; i--)
          // {
          //   printf("%08lx", sign_state.point_r.x[i]);
          // }
          // printf("\ns:");
          // for (i = 7; i >= 0; i--)
          // {
          //   printf("%08lx", sign_state.signature_s[i]);
          // }
          // printf("\n");
          // printf("/signature\n");

              // int i;
      // printf("\n The hash of nonce is : \n");
      // for (i = 0; i < 8; i++)
      // {
      //   printf("%08lx", r_hash->body.hash_nonce_r[i]);
      // }
      // printf("\n---\n");

              // struct msg_contex *strucPtr = &reply_m1.context;
          // unsigned char *charPtr = (unsigned char *)strucPtr;
          // for (i = 0; i < sizeof(struct msg_contex); i++)
          //   {printf("%02x", charPtr[i]);}
          //   printf("\n");

          // NOTE! in sign state the hash is different type : uint32_t hash[12]
          // NOTE! the digest (output) of  sh256 is : uint8_t  buf[64];

          //cast the 8bit pointer to an 32bit pointer
          
          //flip the hash bit (order of uint32_t)
          //the first 8 bytes will be used, the other is padding of 0s
          //Also the output is in reverse bit-order, REV Macro flips the bits
          // i=0

          // printf("\n The hash of nonce is : \n");
          // for (i = 0; i < 32; i++)
          // {
          //   printf("%02x", sha256_digest[i]);
          // }
          // printf("\n---\n");
        
          // j = 7;
          // for (i = 0; i < 8; i++)
          // {
          //   // reply_m1.context.hash_nonce_o[i] = ptr[j];
          //   printf("%08lx", ptr[j]);
          //   j--;
*/