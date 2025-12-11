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

/* GeoNetworking Definitons*/
#define NH_COMMONHEADER 1
#define HT_BEACON 1
#define HT_TSB 5
#define HT_TSB_SHB 0
#define HT_TSB_MULTI_HOP 1
#define ELAPSED_SECONDS 5

#define ITS_EPOCH_MS 1072915200000  // in milliseconds (01-Jan-2004 00:00:00 UTC)
#define CYCLE_SIZE ((uint64_t)1 << 32)

#define IMPLEMENTED_GN_HEADER_TYPES_NUM 2
const u_int implemented_gn_header_types[IMPLEMENTED_GN_HEADER_TYPES_NUM] = {
	HT_BEACON,
	HT_TSB
};


/* BasicTransportProtocol Definitions*/
#define BTP_A 1
#define BTP_B 2
static const struct tok btp_port_values[] = {
    { 2001, "CAM" },
    { 2002, "DENM" },
    { 2003, "MAPEM" },
    { 2004, "SPATEM" },
    { 2005, "SAEM" },
    { 2006, "IVIM" },
    { 2007, "SREM" },
    { 2008, "SSEM" },
    { 2009, "CPM" },
    { 2010, "EVCSN_POI" },
    { 2011, "TPG" },
    { 2012, "EV_RSR" },
    { 2013, "RTCMEM" },
    { 2014, "CTLM" },
    { 2015, "CRLM" },
    { 2016, "EC_AT_REQ" },
    { 2017, "MCDM" },
    { 2018, "VAM" },
    { 2019, "IMZM" },
    { 2020, "DSM" },
    { 2021, "P2P_CRLM" },
    { 2022, "P2P_CTLM" },
    { 2023, "MRS" },
    { 2024, "P2P_FULL_CTLM" },
    { 0, NULL }
};


static int is_header_type_implemented(u_int ht){
	for (u_int i = 0; i < IMPLEMENTED_GN_HEADER_TYPES_NUM; i++){
		if (ht == implemented_gn_header_types[i]){
			return 1;
		}
	}
	return 0;
}

static const char* basic_header_next_header_text_from_bytes(u_int nh){
	switch (nh) {
		case 0: return "Any";
		case 1: return "CommonHeader";
		case 2: return "SecuredPacket";
		default: return "Unknown";
	}
}

static u_int convert_lt_to_seconds(u_int lt_base, u_int lt_multiplier){
	float base_seconds;
	switch (lt_base) {
		case 0:                      // 50 milliseconds
			base_seconds = 0.05;
			break;
		case 1:                      // 1 second
			base_seconds = 1.0;
			break;
		case 2:                      // 10 seconds
			base_seconds = 10.0;
			break;
		case 3:                      // 100 seconds
			base_seconds = 100.0;
			break;
		default:                     // default to 0 second
			base_seconds = 0.0;
			break;
	}
	return (u_int)(base_seconds * lt_multiplier);
}


static void gn_basic_header_decode_from_bytes(netdissect_options *ndo, const u_char **bp, u_int *length, u_int *next_header){
	u_int version;
	u_int reserved;
	u_int lt_multiplier;
	u_int lt_base;
	u_int rhl;

	uint32_t value = GET_BE_U_4(*bp);
	*bp += 4;
	*length -= 4;
	version = (value >> (4 + 3 * 8)) & 0xF;
	*next_header = (value >> (0 + 3 * 8)) & 0xF;
	reserved = (value >> (2 * 8)) & 0xFF;
	lt_multiplier = (value >> 10) & 0x3F;
	lt_base = (value >> 8) & 0x03;
	rhl = value & 0xFF;

	const char* next_header_text = basic_header_next_header_text_from_bytes(*next_header);
	u_int lt_seconds = convert_lt_to_seconds(lt_base, lt_multiplier);
	if (ndo->ndo_vflag == 1) {
		ND_PRINT("ver:%u nh:%s lt:%us rhl:%u; ",
			version, next_header_text, lt_seconds, rhl);
	}else if (ndo->ndo_vflag > 1) {
		ND_PRINT("ver:%u nh:%s reserved:%u lt:[base:%u mult:%u = %us] rhl:%u; ",
			version, next_header_text, reserved,
			lt_base, lt_multiplier, lt_seconds, rhl);
	}
}

static const char* common_header_next_header_text_from_bytes(u_int nh){
	switch (nh) {
		case 0:
			return "Any";
		case 1:
			return "BTP-A";
		case 2:
			return "BTP-B";
		case 3:
			return "IPv6";
		default:
			return "Unknown";
	}
}

static const char* header_type_text_from_bytes(u_int ht, u_int hst){
	switch (ht) {
		case 0:
			return "Any";
		case 1:
			return "Beacon";
		case 2:
			return "GeoUnicast";
		case 3:
			switch (hst) {
				case 0:
					return "GeoAnycastCircle";
				case 1:
					return "GeoAnycastRect";
				case 2:
					return "GeoAnycastElipse";
				default:
					return "Unknown";
			}
		case 4:
			switch (hst) {
				case 0:
					return "GeoBroadcastCircle";
				case 1:
					return "GeoBroadcastRect";
				case 2:
					return "GeoBroadcastElipse";
				default:
					return "Unknown";
			}
		case 5:
			switch (hst) {
				case 0:
					return "TopoScopeBcast-SH";
				case 1:
					return "TopoScopeBcast-MH";
				default:
					return "Unknown";
			}
		case 6:
			switch (hst) {
				case 0:
					return "LocService-Request";
				case 1:
					return "LocService-Reply";
				default:
					return "Unknown";
			}
		default:
			return "Unknown";
	}
}

static const char* flags_text_from_bytes(u_int flags){
	switch (flags) {
		case 0: return "Stationary";
		case 1: return "Mobile";
		default: return "Unknown";
	}
}

static void gn_common_header_decode_from_bytes(netdissect_options *ndo, const u_char **bp, u_int *length, u_int *header_type, u_int *header_subtype, u_int *next_header){
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
	*next_header = (value >> (4 + 7 * 8)) & 0x3;
    reserved = (value >> 7 * 8) & 0xF;
    *header_type = (value >> (4 + 6 * 8)) & 0xF;
    *header_subtype = (value >> 6 * 8) & 0xF;
    
    uint8_t tc_encoded = (value >> 5 * 8) & 0xFF;
	tc_scf = (tc_encoded >> 7) & 0x01;
    tc_channel_offload = (tc_encoded >> 6) & 0x01;
    tc_id = tc_encoded & 0x3F;
    
    flags = (value >> 4 * 8) & 0xFF;
    pl = (value >> 2 * 8) & 0xFFFF;
    mhl = (value >> 8) & 0xFF;
    reserved2 = value & 0xFF;

	const char* next_header_text = common_header_next_header_text_from_bytes(*next_header);
	const char* header_type_text = header_type_text_from_bytes(*header_type, *header_subtype);
	const char* flags_text = flags_text_from_bytes(flags);
	if (ndo->ndo_vflag == 1) {
		ND_PRINT("nh:%s ht:%s f:%s pl:%u mhl:%u; ",
					next_header_text, header_type_text, flags_text, pl, mhl);
	}else if (ndo->ndo_vflag >= 2){
		ND_PRINT("nh:%s reserved:%u ht:%s hst:%u tc:[scf:%u co:%u id:%u] f:%s pl:%u mhl:%u reserved2:%u; ",
			next_header_text, reserved, header_type_text, *header_subtype,
			tc_scf, tc_channel_offload, tc_id,
			flags_text, pl, mhl, reserved2);
	}else{
		ND_PRINT("nh:%s nt:%s; ",
			next_header_text, header_type_text);
	}
}


static const char* st_text_from_bytes(u_int st){
	switch (st){
	case 1: return "Pedestrian";
	case 2: return "Cyclist";
	case 3: return "Moped";
	case 4: return "Motorcycle";
	case 5: return "Passenger Car";
	case 6: return "Bus";
	case 7: return "Light Truck";
	case 8: return "Heavy Truck";
	case 9: return "Trailer";
	case 10: return "Special Vehicle";
	case 11: return "Tram";
	case 12: return "Road Side Unit";
	default: return "Unknown";
	}
}


static const char* process_gn_addr(netdissect_options *ndo, u_int64_t gn_addr){
	u_int8_t m = (gn_addr >> (7 + 7 * 8)) & 0x01; // 1 bit
	u_int8_t st = (gn_addr >> (2 + 7 * 8)) & 0x1F; // 5 bits
	u_int16_t reserved = (gn_addr >> (6 * 8)) & 0x3FF; // 10 bits
	u_int64_t mib = gn_addr & 0xFFFFFFFFFFFF; // 48 bits
	static char buffer[128];
	if (ndo->ndo_vflag >= 1){
		sprintf(buffer, "[m:%u st:%s reserved:%u mib:0x%lx]", m, st_text_from_bytes(st), reserved, mib);
	}else{
		sprintf(buffer, "0x%lx", mib);
	}
	
	return buffer;

}


static const char* process_tst(uint32_t tst) {
    static char buffer[32];

    // Get current UTC time in milliseconds
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    uint64_t ref_utc_ms = (uint64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;

    // Compute number of cycles
    uint64_t adjusted_timestamp = ref_utc_ms - ITS_EPOCH_MS;
    uint64_t number_of_cycles = adjusted_timestamp / CYCLE_SIZE;
	printf("Adjusted timestamp: %lu, Number of cycles: %lu\n", adjusted_timestamp, number_of_cycles);

    // Compute transformed timestamp
    uint64_t transformed_timestamp = tst + CYCLE_SIZE * number_of_cycles + ITS_EPOCH_MS;

    // Correct if transformed_timestamp is in the future
    if (transformed_timestamp > ref_utc_ms) {
        transformed_timestamp = tst + CYCLE_SIZE * (number_of_cycles - 1) + ITS_EPOCH_MS;
    }

    // Split into seconds and milliseconds
    time_t abs_time = transformed_timestamp / 1000;
    uint32_t milliseconds = transformed_timestamp % 1000;

    // Convert to UTC
    struct tm *timeinfo = gmtime(&abs_time);
    if (!timeinfo) {
        snprintf(buffer, sizeof(buffer), "Invalid time");
        return buffer;
    }

    snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d %02d:%02d:%02d.%03u UTC",
             timeinfo->tm_year + 1900,
             timeinfo->tm_mon + 1,
             timeinfo->tm_mday,
             timeinfo->tm_hour,
             timeinfo->tm_min,
             timeinfo->tm_sec,
             milliseconds);

    return buffer;
}

static void process_long_position_vector_from_bytes(netdissect_options *ndo, const u_char **bp, u_int *length){
	u_int64_t gn_addr;
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
	u_int32_t value = GET_BE_U_4(*bp);
	*bp += 4;
	*length -= 4;
	pai = (value >> (7 + 3 * 8)) & 0x01;
	s = (value >> (2 * 8)) / 0x7F;
	h = value & 0xFF;
	if (ndo->ndo_vflag > 1) {
		//ND_PRINT("GN_ADDR:%s tst:%u lat:%u lon:%u pai:%u, s:%u, h:%u; ", process_gn_addr(ndo, gn_addr), tst, lat, lon, pai, s, h);
		ND_PRINT("GN_ADDR:%s tst:%s lat:%u lon:%u pai:%u, s:%u, h:%u; ", process_gn_addr(ndo, gn_addr), process_tst(tst), lat, lon, pai, s, h);
	}else{
		ND_PRINT("GN_ADDR:%s lat:%u, lon:%u; ", process_gn_addr(ndo, gn_addr), lat, lon);
	}
}


static void process_beacon_header_from_bytes(netdissect_options *ndo, const u_char **bp, u_int *length){
	process_long_position_vector_from_bytes(ndo, bp, length);
}


static void process_tsb_shb_header_from_bytes(netdissect_options *ndo, const u_char **bp, u_int *length){

	process_long_position_vector_from_bytes(ndo, bp, length);
	u_int media_indpendenet_data = GET_BE_U_4(*bp);
	*bp += 4;
	*length -= 4;
	if (ndo->ndo_vflag > 2) {
		ND_PRINT("Media-Independent Data: %u; ", media_indpendenet_data);
	}
}

static void process_tsb_header_from_bytes(netdissect_options *ndo, const u_char **bp, u_int *length){
	u_int sn;
	u_int reseved;
	sn = GET_BE_U_2(bp);
	*bp += 2;
	*length -= 2;
	reseved = GET_BE_U_2(bp);
	*bp += 2;
	*length -= 2;
	if (ndo->ndo_vflag > 2) {
		ND_PRINT("sn:%u reserved:%u; ", sn, reseved);
	}
	process_long_position_vector_from_bytes(ndo, bp, length);
}


static void process_optional_extended_header(netdissect_options *ndo, const u_char **bp, u_int *length, u_int header_type, u_int header_subtype){
	switch (header_type){
		case HT_BEACON:
			process_beacon_header_from_bytes(ndo, bp, length);
			return;
			break;
		case HT_TSB:
			switch (header_subtype) {
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

static void process_btp_header_from_bytes(netdissect_options *ndo, const u_char **bp, u_int *length, u_int common_header_next_header){
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
		if (ndo->ndo_vflag > 2) {
			ND_PRINT("BTP-B dst:%s dpi:%u; ", tok2str(btp_port_values, "Unknown", dst_port), dst_port_info);
		} else {	
			ND_PRINT("BTP-B dst:%s; ", tok2str(btp_port_values, "Unknown", dst_port));
		}
		break;	

	default:
		break;
	}
}

void
geonet_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	ndo->ndo_protocol = "geonet";
	ND_PRINT("GeoNet ");

	if (length < 4) {
		ND_PRINT(" (length %u < 4)", length);
		goto invalid;
	}

	/* Process Basic Header */
	u_int basic_header_next_header;
	gn_basic_header_decode_from_bytes(ndo, &bp, &length, &basic_header_next_header);
	if (basic_header_next_header != NH_COMMONHEADER) {
		ND_PRINT(" (Next-Header != CommonHeader)");
		goto invalid;
	}

	/* Process Common Header */
	u_int header_type;
	u_int header_subtype;
	u_int common_header_next_header;
	gn_common_header_decode_from_bytes(ndo, &bp, &length, &header_type, &header_subtype, &common_header_next_header);
	if (!is_header_type_implemented(header_type)) {
		ND_PRINT(" (GeoNetworking Header-Type %s not supported)", header_type_text_from_bytes(header_type, header_subtype));
		goto invalid;
	}

	/* Process Optional Extended Header*/
	process_optional_extended_header(ndo, &bp, &length, header_type, header_subtype);
	if (common_header_next_header == BTP_A || common_header_next_header == BTP_B) {
		/* Print Basic Transport Header */
		process_btp_header_from_bytes(ndo, &bp, &length, common_header_next_header);
	}


	/* Print user data part */
	if (ndo->ndo_vflag)
		ND_DEFAULTPRINT(bp, length);
	return;

invalid:
	nd_print_invalid(ndo);
	/* XXX - print the remaining data as hex? */
}
