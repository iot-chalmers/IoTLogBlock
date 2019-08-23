#ifndef OFFCHAIN_MESSAGE_H
#define OFFCHAIN_MESSAGE_H

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

#endif