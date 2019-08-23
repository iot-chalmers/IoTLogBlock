/*
 * Copyright (c) 2019, Christos Profentzas - www.chalmers.se/~chrpro 
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef OFFCHAIN_MESSAGE_H
#define OFFCHAIN_MESSAGE_H


static const char *const str_res[] = {
    "success",
    "invalid param",
    "NULL error",
    "resource in use",
    "DMA bus error"
};
    
typedef enum
{
  MSG_TYPE_HELLO,      // Init message ( discovery-braodcast)
  MSG_TYPE_READY,      // Init message Ready for exchagne (unicast)
  MSG_TYPE_M1,         // Starting the transcaction
  MSG_TYPE_M2,         // Respond accorgin to ASW protocol
  MSG_TYPE_M3,         // nonce of originator
  MSG_TYPE_M4,         // nonce of Responder
  MSG_TYPE_FOG,        // Connection with fog-edge discovery message
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

//Message 3 of ASW Protocol: Nonce of Reposnder
typedef struct __attribute__((__packed__)) msg_m3
{
  msg_type type;
  short nonce; // Nonce for the Asokan-Shoup-Waidner protocol
} msg_m3;

//Message 3 of ASW Protocol: Nonce of Originator
typedef struct __attribute__((__packed__)) msg_m4
{
  msg_type type;
  short nonce; // Nonce for the Asokan-Shoup-Waidner protocol
} msg_m4;

// A complete Transaction 
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

#endif