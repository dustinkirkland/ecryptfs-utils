/*
 *
 *   Copyright (C) International Business Machines  Corp., 2007
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/*
 * NAME
 *	ecryptfs_generate_tpm_key
 *
 * DESCRIPTION
 *
 *	Generate a sealing (storage) key bound to a specified set of
 *	PCRs values in the current TPM's PCR's. The SRk password is
 *	assumed to be the SHA1 hash of 0 bytes.
 *
 * USAGE
 *	ecryptfs_generate_tpm_key -p 1 -p 2 -p 3
 *
 * HISTORY
 *	v1: Initial revision
 *	v2: Fixed bug in which PCR values were read from the TPM
 *
 *	Author:	Kent Yoder <kyoder@users.sf.net>
 *
 */

#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <trousers/tss.h>
#include <trousers/trousers.h>
#include "config.h"

#define PRINT_ERR(x, ...) fprintf(stderr, "%s:%d Error: " x "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define PRINT_TSS_ERR(s,r) fprintf(stderr, "%s:%d: Error: %s failed: %s\n", __FILE__, __LINE__, s, \
				   Trspi_Error_String(r))

const TSS_UUID SRK_UUID = TSS_UUID_SRK;

void usage(char *name)
{
	fprintf(stderr, "usage: %s <options>\n\n"
		"options: -p <num>\n"
		"         \tBind the key to PCR <num>'s current value\n"
		"         \trepeat this option to bind to more than 1 PCR\n",
		name);
}

char *util_bytes_to_string(char *bytes, int chars)
{
        char *ret = (char *)malloc((chars*2) + 1);
        int i, len = chars*2;

        if (ret == NULL)
                return ret;
        for (i = 0; i < chars; i+=4) {
                sprintf(&ret[i*2], "%02x%02x%02x%02x", bytes[i] & 0xff,
                                bytes[i+1] & 0xff, bytes[i+2] & 0xff,
                                bytes[i+3] & 0xff);
        }
        ret[len] = '\0';
        return ret;
}

int main(int argc, char **argv)
{
	TSS_HKEY hKey, hSRK;
	TSS_HCONTEXT hContext;
	TSS_HTPM hTPM;
	TSS_RESULT result;
	TSS_HPOLICY hPolicy;
	TSS_HPCRS hPcrs;
	UINT32 ulPcrValueLength, subCap, subCapLength;
	UINT32 pulRespDataLength, numPcrs;
	BYTE *pNumPcrs, *rgbPcrValue, *uuidString, *pcrsSelectedValues[24];
	int i, c, *pcrsSelected = NULL, numPcrsSelected = 0;
	TSS_UUID *uuid;
	BYTE wellknown[] = TSS_WELL_KNOWN_SECRET;

	while (1) {
		c = getopt(argc, argv, "p:");
		if (c == -1)
			break;
		switch (c) {
			case 'p':
				numPcrsSelected++;
				pcrsSelected = realloc(pcrsSelected,
						       (sizeof(int) 
							* numPcrsSelected));
				if (pcrsSelected == NULL) {
					PRINT_ERR("Malloc of %zd bytes failed.",
						  (sizeof(int)
						   * numPcrsSelected));
					return -1;
				}
				pcrsSelected[numPcrsSelected - 1] =
					atoi(optarg);
				break;
			default:
				usage(argv[0]);
				break;
		}
	}
	if (numPcrsSelected == 0)
		printf("Warning: Key will not be bound to any PCR's!\n");
	if (numPcrsSelected > 24) {
		PRINT_ERR("Too many PCRs selected! Exiting.");
		return -EINVAL;
	}
        result = Tspi_Context_Create(&hContext);
        if (result != TSS_SUCCESS) {
                PRINT_TSS_ERR("Tspi_Context_Create", result);
                return result;
        }
        result = Tspi_Context_Connect(hContext, NULL);
        if (result != TSS_SUCCESS) {
                PRINT_TSS_ERR("Tspi_Context_Connect", result);
                Tspi_Context_Close(hContext);
                return result;
        }
	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
	if (result != TSS_SUCCESS) {
		PRINT_TSS_ERR("Tspi_Context_GetTpmObject", result);
		Tspi_Context_Close(hContext);
		return result;
	}
	subCap = TSS_TPMCAP_PROP_PCR;
	subCapLength = sizeof(UINT32);
	result = Tspi_TPM_GetCapability(hTPM, TSS_TPMCAP_PROPERTY,
					subCapLength, (BYTE *)&subCap,
					&pulRespDataLength, &pNumPcrs );
	if (result != TSS_SUCCESS) {
		PRINT_TSS_ERR("Tspi_TPM_GetCapability", result);
		Tspi_Context_Close(hContext);
		return result;
	}
	numPcrs = *(UINT32 *)pNumPcrs;
	for (i = 0; i < (int)numPcrsSelected; i++) {
		if (pcrsSelected[i] > (int)numPcrs) {
			fprintf(stderr, "%d: invalid PCR register. PCRs range "
				"from 0 - %u\n", pcrsSelected[i], numPcrs);
			return -1;
		}
	}
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS, 0,
					   &hPcrs);
	if (result != TSS_SUCCESS) {
		PRINT_TSS_ERR("Tspi_Context_CreateObject", result);
		return result;
	}
	for (i = 0; i < numPcrsSelected; i++) {
		result = Tspi_TPM_PcrRead(hTPM, pcrsSelected[i],
					  &ulPcrValueLength, &rgbPcrValue);
		if (result != TSS_SUCCESS) {
			PRINT_TSS_ERR("Tspi_TPM_PcrRead", result);
			Tspi_Context_Close(hContext);
			return result;
		}
		result = Tspi_PcrComposite_SetPcrValue(hPcrs, pcrsSelected[i],
						       ulPcrValueLength,
						       rgbPcrValue);
		if (result != TSS_SUCCESS) {
			PRINT_TSS_ERR("Tspi_PcrComposite_SetPcrValue", result );
			Tspi_Context_Close( hContext );
			return result;
		}

		pcrsSelectedValues[i] = rgbPcrValue;
	}
        result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
					    SRK_UUID, &hSRK);
        if (result != TSS_SUCCESS) {
                PRINT_TSS_ERR("Tspi_Context_LoadKeyByUUID", result);
                Tspi_Context_Close(hContext);
                return result;
        }
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hPolicy);
        if (result != TSS_SUCCESS) {
                PRINT_TSS_ERR("Tspi_GetPolicyObject", result);
                Tspi_Context_Close(hContext);
                return result;
        }

	result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_SHA1,
				       sizeof(wellknown), wellknown);
        if (result != TSS_SUCCESS) {
                PRINT_TSS_ERR("Tspi_GetPolicyObject", result);
                Tspi_Context_Close(hContext);
                return result;
        }
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
					   (TSS_KEY_TYPE_STORAGE
					    | TSS_KEY_SIZE_2048
					    | TSS_KEY_VOLATILE
					    | TSS_KEY_NO_AUTHORIZATION
					    | TSS_KEY_NOT_MIGRATABLE), &hKey);
	if (result != TSS_SUCCESS) {
                PRINT_TSS_ERR("Tspi_Context_CreateObject", result);
                Tspi_Context_Close(hContext);
                return result;
	}
	result = Tspi_Key_CreateKey(hKey, hSRK, hPcrs);
	if (result != TSS_SUCCESS) {
                PRINT_TSS_ERR("Tspi_Key_CreateKey", result);
                Tspi_Context_Close(hContext);
                return result;
	}
	result = Tspi_TPM_GetRandom(hTPM, (UINT32)16, (BYTE **)&uuid);
	if (result != TSS_SUCCESS) {
		PRINT_TSS_ERR("Tspi_TPM_GetRandom", result);
		Tspi_Context_Close(hContext);
		return result;
	}
	result = Tspi_Context_RegisterKey(hContext, hKey, TSS_PS_TYPE_USER,
					  *uuid, TSS_PS_TYPE_SYSTEM, SRK_UUID);
	if (result != TSS_SUCCESS) {
		PRINT_TSS_ERR("Tspi_Context_RegisterKey", result);
		Tspi_Context_Close(hContext);
		return result;
	}
	printf("Success: Key created bound to:\n");
	for (i = 0; i < numPcrsSelected; i++) {
		uuidString = (unsigned char *) 
			      util_bytes_to_string((char *)
						   pcrsSelectedValues[i], 20);
		if (uuidString == NULL) {
			PRINT_ERR("malloc of 41 bytes failed");
			Tspi_Context_Close(hContext);
			return result;
		}

		printf("PCR %d: %s\n", pcrsSelected[i], uuidString);
		free(uuidString);
		Tspi_Context_FreeMemory(hContext, pcrsSelectedValues[i]);
	}
	uuidString = (BYTE *)util_bytes_to_string((char *)uuid, 16);
	if (uuidString == NULL) {
		PRINT_ERR("malloc of 33 bytes failed");
		Tspi_Context_Close(hContext);
		return result;
	}
	printf("And registered in persistent storage with UUID "
	       "(tspi_uuid parameter): %s\n", uuidString);
	Tspi_Context_FreeMemory(hContext, (BYTE *)uuid);
	free(uuidString);
	Tspi_Context_Close(hContext);
	return 0;
}
