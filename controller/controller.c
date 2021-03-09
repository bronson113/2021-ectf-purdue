/*
 * 2021 Collegiate eCTF
 * SCEWL Bus Controller implementation
 * Ben Janis
 *
 * (c) 2021 The MITRE Corporation
 *
 * This source file is part of an example system for MITRE's 2021 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2021 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 */


/*
 * 2021 Purdue Team note:
 * Bronson Yen
 * 
 * The changes are made as follow:
 * 1. changed the registration process to include the exchange of AES key
 * 2. initialize the AES context upon registering 
 * 3. add AES encryption and decrytion for all transmission except the FAA commands
 * 4. add hash to the message to prevent other's from modifying the message
 * 5. add timing flag to packet to prevent replay attack
 *
 *
 */

#include "controller.h"
#include "secret.h"

// this will run if EXAMPLE_AES is defined in the Makefile (see line 54)
#include "aes.h"

#ifdef EXAMPLE_AES
char int2char(uint8_t i) {
  char *hex = "0123456789abcdef";
  return hex[i & 0xf];
}
#endif

#define send_str(M) send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, strlen(M), M)
#define BLOCK_SIZE 16

// message buffer
char buf[SCEWL_MAX_DATA_SZ+0x40];
struct AES_ctx ctx;

// key buffer
uint8_t key[16];
int registered = 0;
int timings[0x100][2];
int t;

int read_msg(intf_t *intf, char *data, scewl_id_t *src_id, scewl_id_t *tgt_id,
             size_t n, int blocking) {
  scewl_hdr_t hdr;
  int read, max;

  // clear buffer and header
  memset(&hdr, 0, sizeof(hdr));
  memset(data, 0, n);

  // find header start
  do {
    hdr.magicC = 0;

    if (intf_read(intf, (char *)&hdr.magicS, 1, blocking) == INTF_NO_DATA) {
      return SCEWL_NO_MSG;
    }

    // check for SC
    if (hdr.magicS == 'S') {
      do {
        if (intf_read(intf, (char *)&hdr.magicC, 1, blocking) == INTF_NO_DATA) {
          return SCEWL_NO_MSG;
        }
      } while (hdr.magicC == 'S'); // in case of multiple 'S's in a row
    }
  } while (hdr.magicS != 'S' && hdr.magicC != 'C');

  // read rest of header
  read = intf_read(intf, (char *)&hdr + 2, sizeof(scewl_hdr_t) - 2, blocking);
  if(read == INTF_NO_DATA) {
    return SCEWL_NO_MSG;
  }

  // unpack header
  *src_id = hdr.src_id;
  *tgt_id = hdr.tgt_id;

  // read body
  max = hdr.len < n ? hdr.len : n;
  read = intf_read(intf, data, max, blocking);

  // throw away rest of message if too long
  for (int i = 0; hdr.len > max && i < hdr.len - max; i++) {
    intf_readb(intf, 0);
  }

  // report if not blocking and full message not received
  if(read == INTF_NO_DATA || read < max) {
    return SCEWL_NO_MSG;
  }

  return max;
}


int send_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, char *data) {
  scewl_hdr_t hdr;

  // pack header
  hdr.magicS  = 'S';
  hdr.magicC  = 'C';
  hdr.src_id = src_id;
  hdr.tgt_id = tgt_id;
  hdr.len    = len;

  // send header
  intf_write(intf, (char *)&hdr, sizeof(scewl_hdr_t));

  // send body
  intf_write(intf, data, len);

  return SCEWL_OK;
}


// handle AES encryption and decryption when recieveing broadcast and direct messages
int handle_scewl_recv(char* data, scewl_id_t src_id, uint16_t len) {
  uint16_t rlen;
  uint32_t rt,rv,h;
  int found = -1;
  for(int i=0;i<len;i+=16){
    AES_ECB_decrypt(&ctx,(uint8_t *)data+i);		
  }

  h = *(uint32_t *)((uint8_t *)(data+len-4));
  rv = *(uint32_t *)((uint8_t *)(data+len-8));
  rlen = *(uint16_t *)((uint8_t *)(data+len-12));
  rt = *(uint32_t *)((uint8_t *)(data+len-16));
  for(int i=0;i<0x100;i++){
  	if(timings[i][0]==src_id){
		if(rt<=timings[i][1])return SCEWL_ERR;
		timings[i][1]=rt;
	}
	if(timings[i][0]==0){found = i;break;}
  }
  if(found!=-1){
	timings[found][0]=src_id;
	timings[found][1]=rt;
  }
  if(rv!=0xdeadbeef)return SCEWL_ERR; 

  uint32_t hash = 0;
  for(int i=0;i<len-16;i+=4){
    hash+=*((uint8_t *)(data+i));
    hash^=*((uint8_t *)(data+i+1));
    hash-=*((uint8_t *)(data+i+2));
    hash*=*((uint8_t *)(data+i+3));
  }
  if(h!=hash) return SCEWL_ERR;
  send_str("Example decrypted message:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, rlen, (char *)data);

  return send_msg(CPU_INTF, src_id, SCEWL_ID, rlen, data);
}


int handle_scewl_send(char* data, scewl_id_t tgt_id, uint16_t len) {  
  uint16_t aligned = (len+15) - ((len+15)%16);
  for(int i=0;i<aligned-len;i++){
    *(uint8_t*)(data+len+i) = 0;
  }

  for(int i=0;i<16;i++){
    *(uint8_t*)(data+i+aligned) = 0;
  }

  uint32_t hash = 0;
  for(int i=0;i<aligned;i+=4){
    hash+=*((uint8_t *)(data+i));
    hash^=*((uint8_t *)(data+i+1));
    hash-=*((uint8_t *)(data+i+2));
    hash*=*((uint8_t *)(data+i+3));
  }

  t+=1;
  *(uint32_t *)((uint8_t *)(data+aligned)) = t;
  *(uint32_t *)((uint8_t *)(data+aligned+4)) = len;
  *(uint32_t *)((uint8_t *)(data+aligned+8)) = 0xdeadbeef;
  *(uint32_t *)((uint8_t *)(data+aligned+12)) = hash;

  for(int i=0;i<aligned+16;i+=16){
    AES_ECB_encrypt(&ctx, (uint8_t *)data+i);		
  }
  
  return send_msg(RAD_INTF, SCEWL_ID, tgt_id, aligned+16, data);
}


int handle_brdcst_recv(char* data, scewl_id_t src_id, uint16_t len) {
  for(int i=0;i<len;i+=16){
    AES_ECB_decrypt(&ctx, (uint8_t *)data+i);		
  }
  return send_msg(CPU_INTF, src_id, SCEWL_BRDCST_ID, len, data);
}


int handle_brdcst_send(char *data, uint16_t len) {
  for(int i=0;i<len;i+=16){
    AES_ECB_encrypt(&ctx, (uint8_t *)data+i);		
  }
  return send_msg(RAD_INTF, SCEWL_ID, SCEWL_BRDCST_ID, (len+15)-((len+15)%16), data);
}   


int handle_faa_recv(char* data, uint16_t len) {
  return send_msg(CPU_INTF, SCEWL_FAA_ID, SCEWL_ID, len, data);
}


int handle_faa_send(char* data, uint16_t len) {
  return send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, data);
}


void handle_registration(char* msg) {
  scewl_sss_msg_t *sss_msg = (scewl_sss_msg_t *)msg;
  if (sss_msg->op == SCEWL_SSS_REG && sss_register()) {
    registered = 1;
  } else if (sss_msg->op == SCEWL_SSS_DEREG && sss_deregister()) {
    registered = 0;
  }
}


int sss_register() {
  scewl_sss_msg_full msg;
  scewl_id_t src_id, tgt_id;
  int status;

  // setup the registration message
  msg.dev_id = SCEWL_ID;
  msg.op = SCEWL_SSS_REG;
  msg.register_number = get_reg_num();
  
  // send registration
  status = send_msg(SSS_INTF, SCEWL_ID, SCEWL_SSS_ID, sizeof(scewl_sss_msg_full), (char *)&msg);
  if (status == SCEWL_ERR) {
    return 0;
  }

  // receive response
  read_msg(SSS_INTF, (char *)&msg, &src_id, &tgt_id, sizeof(scewl_sss_msg_full), 1);

  // retrive the key from the response message
  for(int i=0;i<16;i++){
	  key[i]=*((char *)&msg.key1+i);
  } 

  // initialize the AES context
  AES_init_ctx(&ctx, key);

  // notify CPU of response
  scewl_sss_msg_t cpu_msg;
  cpu_msg.dev_id = msg.dev_id;
  cpu_msg.op = msg.op;

  status = send_msg(CPU_INTF, src_id, tgt_id, sizeof(cpu_msg), (char *)&cpu_msg);
  if (status == SCEWL_ERR) {
    return 0;
  }

  // op should be REG on success
  return msg.op == SCEWL_SSS_REG;
}


int sss_deregister() {
  scewl_sss_msg_full msg;
  scewl_id_t src_id, tgt_id;
  int status;

  // fill registration message
  msg.dev_id = SCEWL_ID;
  msg.op = SCEWL_SSS_DEREG;
  msg.register_number = get_reg_num();
  
  // send registration
  status = send_msg(SSS_INTF, SCEWL_ID, SCEWL_SSS_ID, sizeof(scewl_sss_msg_full), (char *)&msg);
  if (status == SCEWL_ERR) {
    return 0;
  }

  // receive response
  read_msg(SSS_INTF, (char *)&msg, &src_id, &tgt_id, sizeof(scewl_sss_msg_full), 1);

  // notify CPU of response
  scewl_sss_msg_t cpu_msg;
  cpu_msg.dev_id = msg.dev_id;
  cpu_msg.op = msg.op;

  status = send_msg(CPU_INTF, src_id, tgt_id, sizeof(cpu_msg), (char *)&cpu_msg);
  if (status == SCEWL_ERR) {
    return 0;
  }

  // op should be DEREG on success
  return msg.op == SCEWL_SSS_DEREG;
}

int main() {
  int len;
  scewl_hdr_t hdr;
  uint16_t src_id, tgt_id;

  // initialize interfaces
  intf_init(CPU_INTF);
  intf_init(SSS_INTF);
  intf_init(RAD_INTF);


  //initialize interal memory
  t = 0;
  for(int i=0;i<0x100;i++){
	  timings[i][0]=0;
	  timings[i][1]=0;
  }

#ifdef EXAMPLE_AES
  // example encryption using tiny-AES-c
  struct AES_ctx ctx;
  uint8_t plaintext[48] = "0123456789abcdefhellofromtheaesexample";

  for(int i=0;i<16;i++)key[i]=i;


  // initialize context
  AES_init_ctx(&ctx, key);

  // encrypt buffer (encryption happens in place)
  AES_ECB_encrypt(&ctx, plaintext);
  AES_ECB_encrypt(&ctx, plaintext+16);
  AES_ECB_encrypt(&ctx, plaintext+32);
  send_str("Example encrypted message:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 48, (char *)plaintext);

  // decrypt buffer (decryption happens in place)
  AES_ECB_decrypt(&ctx, plaintext);
  AES_ECB_decrypt(&ctx, plaintext+16);
  AES_ECB_decrypt(&ctx, plaintext+32);
  send_str("Example decrypted message:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, 48, (char *)plaintext);
  // end example
#endif

  // serve forever
  while (1) {
    // register with SSS
    read_msg(CPU_INTF, buf, &hdr.src_id, &hdr.tgt_id, sizeof(buf), 1);

    if (hdr.tgt_id == SCEWL_SSS_ID) {
      handle_registration(buf);
    }

    // server while registered
    while (registered) {
      memset(&hdr, 0, sizeof(hdr));

      // handle outgoing message from CPU
      if (intf_avail(CPU_INTF)) {
        // Read message from CPU
        len = read_msg(CPU_INTF, buf, &src_id, &tgt_id, sizeof(buf), 1);

        if (tgt_id == SCEWL_BRDCST_ID) {
          handle_brdcst_send(buf, len);
        } else if (tgt_id == SCEWL_SSS_ID) {
          handle_registration(buf);
        } else if (tgt_id == SCEWL_FAA_ID) {
          handle_faa_send(buf, len);
        } else {
          handle_scewl_send(buf, tgt_id, len);
        }

        continue;
      }

      // handle incoming radio message
      if (intf_avail(RAD_INTF)) {
        // Read message from antenna
        len = read_msg(RAD_INTF, buf, &src_id, &tgt_id, sizeof(buf), 1);

        if (src_id != SCEWL_ID) { // ignore our own outgoing messages
          if (tgt_id == SCEWL_BRDCST_ID) {
            // receive broadcast message
            handle_brdcst_recv(buf, src_id, len);
          } else if (tgt_id == SCEWL_ID) {
            // receive unicast message
            if (src_id == SCEWL_FAA_ID) {
              handle_faa_recv(buf, len);
            } else {
              handle_scewl_recv(buf, src_id, len);
            }
          }
        }
      }
    }
  }
}
