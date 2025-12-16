/*
 * Copyright (c) 2013 The TCPDUMP project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code
 * distributions retain the above copyright notice and this paragraph
 * in its entirety, and (2) distributions including binary code include
 * the above copyright notice and this paragraph in its entirety in
 * the documentation or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND
 * WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
 * LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE.
 *
 * Original code by Ola Martin Lykkja (ola.lykkja@q-free.com).
 * Updated code by Daniel Ulied (daniel.ulied@i2cat.net) and Jordi Marias-Parella (jordi.marias@i2cat.net).
 */

/* \summary: ETSI GeoNetworking & Basic Transport Protocol printer */

#include <config.h>

#include "netdissect-stdinc.h"

#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "extract.h"
#include "addrtoname.h"

/*
   ETSI EN 302 636-5-1 V2.2.1 (2019-05)
   Intelligent Transport Systems (ITS);
   Vehicular Communications;
   GeoNetworking;
   Part 5: Transport Protocols;
   Sub-part 1: Basic Transport Protocol

   ETSI EN 302 636-4-1 V1.4.1 (2020-01)
   Intelligent Transport Systems (ITS);
   Vehicular Communications;
   GeoNetworking;
   Part 4: Geographical addressing and forwarding for point-to-point and point-to-multipoint communications;
   Sub-part 1: Media-Independent Functionality;
   Release 2
*/

/*Specific Definitions*/
#define NDO_V_FLAG_FIRST_DEBUG_LEVEL 1
#define NDO_V_FLAG_SECOND_DEBUG_LEVEL 2
#define NDO_V_FLAG_THIRD_DEBUG_LEVEL 3

/*Bit-Wise Definitions*/
#define ONE_BYTE 8
#define TWO_BYTES 16
#define THREE_BYTES 24
#define FOUR_BYTES 32
#define FIVE_BYTES 40
#define SIX_BYTES 48
#define SEVEN_BYTES 56
#define EIGHT_BYTES 64

#define ONE_BIT_MASK 0x01
#define TWO_BITS_MASK 0x03
#define THREE_BITS_MASK 0x07
#define FOUR_BITS_MASK 0x0F
#define FIVE_BITS_MASK 0x1F
#define SIX_BITS_MASK 0x3F
#define SEVEN_BITS_MASK 0x7F
#define EIGHT_BITS_MASK 0xFF
#define TEN_BITS_MASK 0x3FF
#define SIXTEEN_BITS_MASK 0xFFFF
#define FORTY_EIGHT_BITS_MASK 0xFFFFFFFFFFFF

/* GeoNetworking Definitons*/

/* GeoNetworking Basic Header Definitions*/
#define GN_BASIC_HEADER_MINIMUM_PACKET_LENGTH 4

#define IMPLEMENTED_GN_VERSIONS_NUM 1
static const u_int implemented_gn_versions[IMPLEMENTED_GN_VERSIONS_NUM] = {1};

#define NH_COMMONHEADER 1
#define NH_SECUREDPACKET 2
#define IMPLEMENTED_GN_NEXT_HEADERS_NUM 1
static const u_int implemented_gn_nh_headers[IMPLEMENTED_GN_NEXT_HEADERS_NUM] = {
	NH_COMMONHEADER};
static const struct tok basic_header_next_header_values[] = {
	{0, "Any"},
	{NH_COMMONHEADER, "CommonHeader"},
	{NH_SECUREDPACKET, "SecuredPacket"},
};

#define HT_BEACON 1
#define HT_TSB 5
#define HT_TSB_SHB 0
#define HT_TSB_MULTI_HOP 1
#define ELAPSED_SECONDS 5

#define IMPLEMENTED_GN_HEADER_TYPES_NUM 2
static const u_int implemented_gn_header_types[IMPLEMENTED_GN_HEADER_TYPES_NUM] = {
	HT_BEACON,
	HT_TSB};

static const struct tok common_header_next_header_values[] = {
	{0, "Any"},
	{1, "BTP-A"},
	{2, "BTP-B"},
	{3, "IPv6"},
};

#define HT_HST(ht, hst) (((ht) << 8) | (hst))
static const struct tok header_type_tok[] = {
	{HT_HST(0, 0), "Any"},

	{HT_HST(1, 0), "Beacon"},

	{HT_HST(2, 0), "GeoUnicast"},

	{HT_HST(3, 0), "GeoAnycastCircle"},
	{HT_HST(3, 1), "GeoAnycastRect"},
	{HT_HST(3, 2), "GeoAnycastElipse"},

	{HT_HST(4, 0), "GeoBroadcastCircle"},
	{HT_HST(4, 1), "GeoBroadcastRect"},
	{HT_HST(4, 2), "GeoBroadcastElipse"},

	{HT_HST(5, 0), "TopoScopeBcast-SH"},
	{HT_HST(5, 1), "TopoScopeBcast-MH"},

	{HT_HST(6, 0), "LocService-Request"},
	{HT_HST(6, 1), "LocService-Reply"},
};

static const struct tok flags_text_from_bytes[] = {
	{0, "Stationary"},
	{1, "Mobile"},
};

static const struct tok st_text_from_bytes[] = {
	{1, "Pedestrian"},
	{2, "Cyclist"},
	{3, "Moped"},
	{4, "Motorcycle"},
	{5, "Passenger Car"},
	{6, "Bus"},
	{7, "Light Truck"},
	{8, "Heavy Truck"},
	{9, "Trailer"},
	{10, "Special Vehicle"},
	{11, "Tram"},
	{12, "Road Side Unit"},
};

/* BasicTransportProtocol Definitions*/
#define BTP_A 1
#define BTP_B 2
static const struct tok btp_port_values[] = {
	{2001, "CAM"},
	{2002, "DENM"},
	{2003, "MAPEM"},
	{2004, "SPATEM"},
	{2005, "SAEM"},
	{2006, "IVIM"},
	{2007, "SREM"},
	{2008, "SSEM"},
	{2009, "CPM"},
	{2010, "EVCSN_POI"},
	{2011, "TPG"},
	{2012, "EV_RSR"},
	{2013, "RTCMEM"},
	{2014, "CTLM"},
	{2015, "CRLM"},
	{2016, "EC_AT_REQ"},
	{2017, "MCDM"},
	{2018, "VAM"},
	{2019, "IMZM"},
	{2020, "DSM"},
	{2021, "P2P_CRLM"},
	{2022, "P2P_CTLM"},
	{2023, "MRS"},
	{2024, "P2P_FULL_CTLM"},
	{0, NULL}};

static int is_header_type_implemented(u_int ht)
{
	for (u_int i = 0; i < IMPLEMENTED_GN_HEADER_TYPES_NUM; i++)
	{
		if (ht == implemented_gn_header_types[i])
		{
			return 1;
		}
	}
	return 0;
}

static u_int convert_lt_to_seconds(u_int lt_base, u_int lt_multiplier)
{
	float base_seconds;
	switch (lt_base)
	{
	case 0: // 50 milliseconds
		base_seconds = 0.05;
		break;
	case 1: // 1 second
		base_seconds = 1.0;
		break;
	case 2: // 10 seconds
		base_seconds = 10.0;
		break;
	case 3: // 100 seconds
		base_seconds = 100.0;
		break;
	default: // default to 0 second
		base_seconds = 0.0;
		break;
	}
	return (u_int)(base_seconds * lt_multiplier);
}

static void gn_basic_header_decode_from_bytes(netdissect_options *ndo, const u_char **bp, u_int *length, u_int *next_header)
{
	u_int version;
	u_int reserved;
	u_int lt_multiplier;
	u_int lt_base;
	u_int rhl;

	uint32_t value = GET_BE_U_4(*bp);
	*bp += 4;
	*length -= 4;
	version = (value >> (4 + THREE_BYTES)) & FOUR_BITS_MASK;
	if (!memchr(implemented_gn_versions, version, IMPLEMENTED_GN_VERSIONS_NUM))
	{
		ND_PRINT(" (Unsupported GeoNetworking Basic Header version %u)", version);
		*next_header = 0; // Indicates an error.
		return;
	}
	*next_header = (value >> (THREE_BYTES)) & FOUR_BITS_MASK;
	reserved = (value >> (TWO_BYTES)) & EIGHT_BITS_MASK;
	lt_multiplier = (value >> (2 + ONE_BYTE)) & SIX_BITS_MASK;
	lt_base = (value >> ONE_BYTE) & THREE_BITS_MASK;
	rhl = value & FOUR_BITS_MASK;

	const char *next_header_text = tok2str(basic_header_next_header_values, "Unknown", *next_header);
	u_int lt_seconds = convert_lt_to_seconds(lt_base, lt_multiplier);
	if (ndo->ndo_vflag == NDO_V_FLAG_FIRST_DEBUG_LEVEL)
	{
		ND_PRINT("ver:%u nh:%s lt:%us rhl:%u; ",
				 version, next_header_text, lt_seconds, rhl);
	}
	else if (ndo->ndo_vflag > NDO_V_FLAG_FIRST_DEBUG_LEVEL)
	{
		ND_PRINT("ver:%u nh:%s reserved:%u lt:[base:%u mult:%u = %us] rhl:%u; ",
				 version, next_header_text, reserved,
				 lt_base, lt_multiplier, lt_seconds, rhl);
	}
}

static void gn_common_header_decode_from_bytes(netdissect_options *ndo, const u_char **bp, u_int *length, u_int *header_type, u_int *header_subtype, u_int *next_header)
{
	u_int reserved;
	u_int tc_scf;
	u_int tc_channel_offload;
	u_int tc_id;
	u_int flags;
	u_int pl;
	u_int mhl;
	u_int reserved2;

	uint64_t value = GET_BE_U_8(*bp);
	*bp += 8;
	*length -= 8;
	*next_header = (value >> (4 + SEVEN_BYTES)) & THREE_BITS_MASK;
	reserved = (value >> SEVEN_BYTES) & FOUR_BITS_MASK;
	*header_type = (value >> (4 + SIX_BYTES)) & FOUR_BITS_MASK;
	*header_subtype = (value >> SIX_BYTES) & FOUR_BITS_MASK;

	uint8_t tc_encoded = (value >> FIVE_BYTES) & EIGHT_BITS_MASK;
	tc_scf = (tc_encoded >> 7) & ONE_BIT_MASK;
	tc_channel_offload = (tc_encoded >> 6) & ONE_BIT_MASK;
	tc_id = tc_encoded & SIX_BITS_MASK;

	flags = (value >> FOUR_BYTES) & EIGHT_BITS_MASK;
	pl = (value >> TWO_BYTES) & SIXTEEN_BITS_MASK;
	mhl = (value >> ONE_BYTE) & EIGHT_BITS_MASK;
	reserved2 = value & EIGHT_BITS_MASK;

	const char *next_header_text = tok2str(common_header_next_header_values, "Unknown", *next_header);
	const char *header_type_text = tok2str(header_type_tok, "Unknown", HT_HST(*header_type, *header_subtype));
	const char *flags_text = tok2str(flags_text_from_bytes, "Unknown", flags);
	if (ndo->ndo_vflag == 1)
	{
		ND_PRINT("nh:%s ht:%s f:%s pl:%u mhl:%u; ",
				 next_header_text, header_type_text, flags_text, pl, mhl);
	}
	else if (ndo->ndo_vflag >= 2)
	{
		ND_PRINT("nh:%s reserved:%u ht:%s hst:%u tc:[scf:%u co:%u id:%u] f:%s pl:%u mhl:%u reserved2:%u; ",
				 next_header_text, reserved, header_type_text, *header_subtype,
				 tc_scf, tc_channel_offload, tc_id,
				 flags_text, pl, mhl, reserved2);
	}
	else
	{
		ND_PRINT("nh:%s nt:%s; ",
				 next_header_text, header_type_text);
	}
}

static const char *process_gn_addr(netdissect_options *ndo, uint64_t gn_addr)
{
	uint8_t m = (gn_addr >> (7 + SEVEN_BYTES)) & ONE_BIT_MASK;
	uint8_t st = (gn_addr >> (2 + SEVEN_BYTES)) & FIVE_BITS_MASK;
	uint16_t reserved = (gn_addr >> SIX_BYTES) & TEN_BITS_MASK; // 10 bits
	uint64_t mib = gn_addr & FORTY_EIGHT_BITS_MASK;				// 48 bits
	static char buffer[128];
	if (ndo->ndo_vflag >= NDO_V_FLAG_FIRST_DEBUG_LEVEL)
	{
		sprintf(buffer, "[m:%u st:%s reserved:%u mib:0x%llx]", m, tok2str(st_text_from_bytes, "Unknown", st), reserved, (unsigned long long)mib);
	}
	else
	{
		sprintf(buffer, "0x%llx", (unsigned long long)mib);
	}

	return buffer;
}

static void process_long_position_vector_from_bytes(netdissect_options *ndo, const u_char **bp, u_int *length)
{
	uint64_t gn_addr;
	u_int tst;
	u_int lat;
	u_int lon;
	u_int pai;
	u_int s;
	u_int h;

	gn_addr = GET_BE_U_8(*bp);
	*bp += 8;
	*length -= 8;
	tst = GET_BE_U_4(*bp);
	*bp += 4;
	*length -= 4;
	lat = GET_BE_U_4(*bp);
	*bp += 4;
	*length -= 4;
	lon = GET_BE_U_4(*bp);
	*bp += 4;
	*length -= 4;
	uint32_t value = GET_BE_U_4(*bp);
	*bp += 4;
	*length -= 4;
	pai = (value >> (7 + THREE_BYTES)) & ONE_BIT_MASK;
	s = (value >> TWO_BYTES) / SEVEN_BITS_MASK;
	h = value & EIGHT_BITS_MASK;
	if (ndo->ndo_vflag > NDO_V_FLAG_FIRST_DEBUG_LEVEL)
	{
		ND_PRINT("GN_ADDR:%s tst:%u lat:%u lon:%u pai:%u, s:%u, h:%u; ", process_gn_addr(ndo, gn_addr), tst, lat, lon, pai, s, h);
	}
	else
	{
		ND_PRINT("GN_ADDR:%s lat:%u, lon:%u; ", process_gn_addr(ndo, gn_addr), lat, lon);
	}
}

static void process_beacon_header_from_bytes(netdissect_options *ndo, const u_char **bp, u_int *length)
{
	process_long_position_vector_from_bytes(ndo, bp, length);
}

static void process_tsb_shb_header_from_bytes(netdissect_options *ndo, const u_char **bp, u_int *length)
{

	process_long_position_vector_from_bytes(ndo, bp, length);
	u_int media_indpendenet_data = GET_BE_U_4(*bp);
	*bp += 4;
	*length -= 4;
	if (ndo->ndo_vflag > NDO_V_FLAG_SECOND_DEBUG_LEVEL)
	{
		ND_PRINT("Media-Independent Data: %u; ", media_indpendenet_data);
	}
}

static void process_tsb_header_from_bytes(netdissect_options *ndo, const u_char **bp, u_int *length)
{
	u_int sn;
	u_int reseved;
	sn = GET_BE_U_2(bp);
	*bp += 2;
	*length -= 2;
	reseved = GET_BE_U_2(bp);
	*bp += 2;
	*length -= 2;
	if (ndo->ndo_vflag > 2)
	{
		ND_PRINT("sn:%u reserved:%u; ", sn, reseved);
	}
	process_long_position_vector_from_bytes(ndo, bp, length);
}

static void process_optional_extended_header(netdissect_options *ndo, const u_char **bp, u_int *length, u_int header_type, u_int header_subtype)
{
	switch (header_type)
	{
	case HT_BEACON:
		process_beacon_header_from_bytes(ndo, bp, length);
		return;
		break;
	case HT_TSB:
		switch (header_subtype)
		{
		case 0:
			process_tsb_shb_header_from_bytes(ndo, bp, length);
			break;
		case 1:
			process_tsb_header_from_bytes(ndo, bp, length);
			break;
		default:
			ND_PRINT(" (TSB Header-Subtype not supported)");
			break;
		}
		break;
	default:
		ND_PRINT(" (Header-Type not supported)");
		break;
	}
}

static void process_btp_header_from_bytes(netdissect_options *ndo, const u_char **bp, u_int *length, u_int common_header_next_header)
{
	u_int dst_port;
	u_int src_port;
	u_int dst_port_info;

	dst_port = GET_BE_U_2(*bp);
	*bp += 2;
	*length -= 2;

	switch (common_header_next_header)
	{
	case BTP_A:
		src_port = GET_BE_U_2(*bp);
		*bp += 2;
		*length -= 2;
		ND_PRINT("BTP-A dst:%s src:%s; ", tok2str(btp_port_values, "Unknown", dst_port), tok2str(btp_port_values, "Unknown", src_port));
		break;

	case BTP_B:
		dst_port_info = GET_BE_U_2(*bp);
		*bp += 2;
		*length -= 2;
		if (ndo->ndo_vflag > 2)
		{
			ND_PRINT("BTP-B dst:%s dpi:%u; ", tok2str(btp_port_values, "Unknown", dst_port), dst_port_info);
		}
		else
		{
			ND_PRINT("BTP-B dst:%s; ", tok2str(btp_port_values, "Unknown", dst_port));
		}
		break;

	default:
		break;
	}
}

void geonet_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	ndo->ndo_protocol = "geonet";
	ND_PRINT("GeoNet ");

	if (length < GN_BASIC_HEADER_MINIMUM_PACKET_LENGTH)
	{
		ND_PRINT(" (length %u < %u)", length, GN_BASIC_HEADER_MINIMUM_PACKET_LENGTH);
		goto invalid;
	}

	/* Process Basic Header */
	u_int basic_header_next_header;
	gn_basic_header_decode_from_bytes(ndo, &bp, &length, &basic_header_next_header);
	if (!memchr(implemented_gn_nh_headers, basic_header_next_header, IMPLEMENTED_GN_NEXT_HEADERS_NUM))
	{
		ND_PRINT(" (Next-Header not supported: %s)", tok2str(basic_header_next_header_values, "Unknown", basic_header_next_header));
		goto invalid;
	}

	/* Process Common Header */
	u_int header_type;
	u_int header_subtype;
	u_int common_header_next_header;
	gn_common_header_decode_from_bytes(ndo, &bp, &length, &header_type, &header_subtype, &common_header_next_header);
	if (!is_header_type_implemented(header_type))
	{
		ND_PRINT(" (GeoNetworking Header-Type %s not supported)", tok2str(header_type_tok, "Unknown", HT_HST(header_type, header_subtype)));
		goto invalid;
	}

	/* Process Optional Extended Header*/
	process_optional_extended_header(ndo, &bp, &length, header_type, header_subtype);
	if (common_header_next_header == BTP_A || common_header_next_header == BTP_B)
	{
		/* Print Basic Transport Header */
		process_btp_header_from_bytes(ndo, &bp, &length, common_header_next_header);
	}

	/* Print user data part */
	if (ndo->ndo_vflag)
		ND_DEFAULTPRINT(bp, length);
	return;

invalid:
	nd_print_invalid(ndo);
}
