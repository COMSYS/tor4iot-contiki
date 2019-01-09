/*
 * Copyright (c) 2015, Benoît Thébaudeau <benoit.thebaudeau.dev@gmail.com>
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
/**
 * \addtogroup cc2538-examples
 * @{
 *
 * \defgroup cc2538-ctr-test cc2538d AES-CTR Test Project
 *
 *   AES-CTR access example for CC2538-based platforms
 *
 *   This example shows how AES-CTR should be used. The example also verifies
 *   the AES-CTR functionality.
 *
 * @{
 *
 * \file
 *     Example demonstrating AES-CTR
 */
#include "contiki.h"
#include "sys/rtimer.h"
#include "dev/rom-util.h"
#include "dev/ctr-state.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
/*---------------------------------------------------------------------------*/
#define NONCE_MAX_LEN   0
#define ICTR_MAX_LEN    16
#define MDATA_MAX_LEN   64
/*---------------------------------------------------------------------------*/
PROCESS(ctr_test_process, "ctr test process");
AUTOSTART_PROCESSES(&ctr_test_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(ctr_test_process, ev, data)
{
  uint8_t test_key_128[]  = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  uint8_t test_key_256[]  = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
                             0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  uint8_t test_iv[]       = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
  uint8_t test_in[]       = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
  uint8_t test_out_128[]  = {0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce};
  uint8_t test_out2_128[] = {0x5d, 0xea, 0xc2, 0xde, 0x49, 0x33, 0xce, 0xf5, 0xf1, 0x9d, 0x09, 0xc6, 0x8f, 0xc3, 0x64, 0x84};

  uint8_t test_out_256[]  = {0x9e, 0xd0, 0xb8, 0xb9, 0xc9, 0xbe, 0x50, 0xe1, 0x75, 0xdc, 0x80, 0x62, 0x82, 0x43, 0x37, 0x72};
  uint8_t test_out2_256[] = {0xb7, 0x59, 0x90, 0x83, 0x07, 0xf2, 0xbc, 0x2c, 0xec, 0xdf, 0x6b, 0xde, 0x60, 0x4a, 0x1b, 0xb3};
  uint8_t buf[16];

  static aes_ctr_state_ctx ctx;

  PROCESS_BEGIN();

  puts("-----------------------------------------\n"
       "Initializing cryptoprocessor...");
  crypto_init();

  puts("Testing AES-128 CTR now... ");

  ctr_state_init(&ctx, test_key_128, 16, test_iv);
  memcpy(buf, test_in, 16);

  ctr_state_crypt(&ctx, buf, 8);

  ctr_state_crypt(&ctx, buf+8, 8);

  for (uint8_t i=0; i<16; i++) {
      if (buf[i] != test_out_128[i]) {
        printf("0x%02x : 0x%02x\n", buf[i], test_out_128[i]);
        puts("FAILED!\n");
        //break;
      }
    }

  memcpy(buf, test_in, 16);
  ctr_state_crypt(&ctx, buf, 16);

  for (uint8_t i=0; i<16; i++) {
    if (buf[i] != test_out2_128[i]) {
      puts("FAILED!\n");
      break;
    }
  }

  puts("OK!\n");


  puts("Testing AES-256 CTR now... ");
  memset(&ctx, 0, sizeof(aes_ctr_state_ctx));

  ctr_state_init(&ctx, test_key_256, 32, test_iv);
  memcpy(buf, test_in, 16);
  ctr_state_crypt(&ctx, buf, 8);

  ctr_state_crypt(&ctx, buf+8, 8);

  for (uint8_t i=0; i<16; i++) {
    if (buf[i] != test_out_256[i]) {
      printf("0x%02x : 0x%02x\n", buf[i], test_out_256[i]);
      puts("FAILED!\n");
      //break;
    }
  }

  memcpy(buf, test_in, 16);
  ctr_state_crypt(&ctx, buf, 16);

  for (uint8_t i=0; i<16; i++) {
    if (buf[i] != test_out2_256[i]) {
      printf("0x%02x : 0x%02x\n", buf[i], test_out2_256[i]);
      puts("FAILED!\n");
      //break;
    }
  }

  puts("OK!\n");

  puts("-----------------------------------------\n"
       "Disabling cryptoprocessor...");
  crypto_disable();

  puts("Done!");

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
/**
 * @}
 * @}
 */
