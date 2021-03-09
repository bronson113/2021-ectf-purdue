/*
 * 2021 Collegiate eCTF
 * Example echo client
 * Ben Janis
 *
 * (c) 2021 The MITRE Corporation
 *
 * This source file is part of an example system for MITRE's 2021 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2021 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 */

#include "scewl_bus_driver/scewl_bus.h"

#include <stdio.h>
#include <string.h>

#define BUF_SZ 0x4080

// SCEWL_ID and TGT_ID need to be defined at compile
#ifndef TGT_ID
#warning TGT_ID not defined, using bad default of 0xffff
#define TGT_ID ((scewl_id_t)0xffff)
#endif


// trust me, it's easier to get the boot reference flag by
// following the instructions than to try to untangle this
// NOTE: you're not allowed to do this in your code
typedef uint32_t aErjfkdfru;const uint32_t flag_as[]={0x1ffe4b6,0x3098ac,
0x2f56101,0x11a38bb,0x485124,0x11644a7,0x3c74e8,0x3c74e8,0x2f56101,0x2ca498,
0x3098ac,0x1fbf0a2,0x11a38bb,0x1ffe4b6,0x3098ac,0x3c74e8,0x11a38bb,0x11a38bb,
0x1ffe4b6,0x1ffe4b6,0x1cc7fb2,0x1fbf0a2,0x51bd0,0x51bd0,0x1ffe4b6,0x1d073c6,
0x2179d2e,0};const uint32_t flag_bs[]={0x138e798,0x2cdbb14,0x1f9f376,0x23bcfda,
0x1d90544,0x1cad2d2,0x860e2c,0x860e2c,0x1f9f376,0x25cbe0c,0x2cdbb14,0xc7ea90,
0x23bcfda,0x138e798,0x2cdbb14,0x860e2c,0x23bcfda,0x23bcfda,0x138e798,0x138e798,
0x2b15630,0xc7ea90,0x18d7fbc,0x18d7fbc,0x138e798,0x3225338,0x4431c8,0};
typedef int skerufjp; skerufjp siNfidpL(skerufjp verLKUDSfj){aErjfkdfru 
ubkerpYBd=12+1;skerufjp xUrenrkldxpxx=2253667944%0x432a1f32;aErjfkdfru UfejrlcpD=
1361423303;verLKUDSfj=(verLKUDSfj+0x12345678)%60466176;while(
xUrenrkldxpxx--!=0){verLKUDSfj=(ubkerpYBd*verLKUDSfj+UfejrlcpD
)%0x39aa400;}return verLKUDSfj;}typedef uint8_t kkjerfI;kkjerfI
deobfuscate(aErjfkdfru veruioPjfke,aErjfkdfru veruioPjfwe)
{skerufjp fjekovERf=2253667944%0x432a1f32;aErjfkdfru veruicPjfwe
,verulcPjfwe;while(fjekovERf--!=0){veruioPjfwe=(veruioPjfwe
-siNfidpL(veruioPjfke))%0x39aa400;veruioPjfke=(veruioPjfke-
siNfidpL(veruioPjfwe))%60466176;}veruicPjfwe=(veruioPjfke+
0x39aa400)%60466176;verulcPjfwe=(veruioPjfwe+
60466176)%0x39aa400;return veruicPjfwe*60466176+verulcPjfwe-89;}


int main(void) {
  scewl_id_t src_id, tgt_id;
  uint16_t len;
  char *msg = "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";
  char data[BUF_SZ];

  // open log file
  FILE *log = stderr;
  // NOTE: you can write to a file inside the Docker container instead:
  // FILE *log = fopen("cpu.log", "a");

  // initialize SCEWL
  scewl_init();

  // register
  if (scewl_register() != SCEWL_OK) {
    fprintf(log, "BAD REGISTRATION! Reregistering...\n");
    if (scewl_deregister() != SCEWL_OK) {
      fprintf(log, "BAD DEREGISTRATION!\n");
      return 1;
    }
    if (scewl_register() != SCEWL_OK) {
      fprintf(log, "BAD REGISTRATION! CANNOT RECOVER\n");
      return 1;
    }
  }

  fprintf(log, "Sending hello...\n");
  scewl_send(TGT_ID, 0x1001, msg);

  // receive response (block until response received)
  fprintf(log, "Waiting for response...\n");
  scewl_recv(data, &src_id, &tgt_id, BUF_SZ, 1);

  // check if response matches
  if (!strcmp(msg, data)) {
    // decode and print flag
    uint8_t flag[32] = {0};
    for (int i = 0; flag_as[i]; i++) {
      flag[i] = deobfuscate(flag_as[i], flag_bs[i]);
      flag[i+1] = 0;
    }
    fprintf(log, "Congrats on booting the system! Press <enter> on the FAA transceiver to view your flag!\n");
    scewl_send(SCEWL_FAA_ID, strlen(flag), flag);
  } else {
    fprintf(log, "Bad response!\n");
  }

  // deregister
  fprintf(log, "Deregistering...\n");
  if (scewl_deregister() != SCEWL_OK) {
    fprintf(log, "BAD DEREGISTRATION!\n");
  }
  fprintf(log, "Exiting...\n");
}
