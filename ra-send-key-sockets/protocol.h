/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/

#ifndef __PROTOCOL_H
#define __PROTOCOL_H

#include <inttypes.h>
#include <sgx_quote.h>

/*
 * Define a structure to be used to transfer the Attestation Status 
 * from Server to client and include the Platform Info Blob in base16 
 * format as Message 4.
 *
 * The structure of Message 4 is not defined by SGX: it is up to the
 * service provider, and can include more than just the attestation
 * status and platform info blob.
 */

/*
 * This doesn't have to be binary. 
 */

typedef enum {
	NotTrusted = 0,
	NotTrusted_ItsComplicated,
	Trusted_ItsComplicated,
	Trusted
} attestation_status_t;

typedef struct _ra_msg4_struct {
	attestation_status_t status;
	sgx_platform_info_t platformInfoBlob;
    // sp_aes_gcm_data_t secret;
	uint32_t body_size;
	uint8_t body[8];
} ra_msg4_t;

// typedef struct sp_aes_gcm_data_t {
//     uint32_t        payload_size;       /*  0: Size of the payload which is*/
//                                         /*     encrypted*/
//     uint8_t         reserved[12];       /*  4: Reserved bits*/
//     uint8_t         payload_tag[SAMPLE_SP_TAG_SIZE];
//                                         /* 16: AES-GMAC of the plain text,*/
//                                         /*     payload, and the sizes*/
//     uint8_t         payload[];          /* 32: Ciphertext of the payload*/
//                                         /*     followed by the plain text*/
// } sp_aes_gcm_data_t;

#endif

