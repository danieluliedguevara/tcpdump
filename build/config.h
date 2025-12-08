/* cmakeconfig.h.in */

#ifndef TCPDUMP_CONFIG_H_
#define TCPDUMP_CONFIG_H_

/* Define to 1 if arpa/inet.h declares `ether_ntohost' */
/* #undef ARPA_INET_H_DECLARES_ETHER_NTOHOST */

/* define if you want to build the possibly-buggy SMB printer */
/* #undef ENABLE_SMB */

/* Define to 1 if you have the `bpf_dump' function. */
#define HAVE_BPF_DUMP 1

/* capsicum support available */
/* #undef HAVE_CAPSICUM */

/* Define to 1 if you have the `cap_enter' function. */
/* #undef HAVE_CAP_ENTER */

/* Define to 1 if you have the `cap_ioctls_limit' function. */
/* #undef HAVE_CAP_IOCTLS_LIMIT */

/* Define to 1 if you have the <cap-ng.h> header file. */
/* #undef HAVE_CAP_NG_H */

/* Define to 1 if you have the `cap_rights_limit' function. */
/* #undef HAVE_CAP_RIGHTS_LIMIT */

/* Casper support available */
/* #undef HAVE_CASPER */

/* Define to 1 if you have the declaration of `ether_ntohost' */
#define HAVE_DECL_ETHER_NTOHOST 1

/* Define to 1 if you have the `ether_ntohost' function. */
#define HAVE_ETHER_NTOHOST 1

/* Define to 1 if you have the `EVP_CIPHER_CTX_new' function. */
/* #undef HAVE_EVP_CIPHER_CTX_NEW */

/* Define to 1 if you have the `EVP_DecryptInit_ex' function. */
/* #undef HAVE_EVP_DECRYPTINIT_EX */

/* Define to 1 if you have the `fork' function. */
#define HAVE_FORK 1

/* Define to 1 if you have the `getopt_long' function. */
#define HAVE_GETOPT_LONG 1

/* define if you have getrpcbynumber() */
#define HAVE_GETRPCBYNUMBER 1

/* Define to 1 if you have the `getservent' function. */
#define HAVE_GETSERVENT 1

/* Define to 1 if you have the `cap-ng' library (-lcap-ng). */
/* #undef HAVE_LIBCAP_NG */

/* Define to 1 if you have a usable `crypto' library (-lcrypto). */
/* #undef HAVE_LIBCRYPTO */

/* Define to 1 if you have the `rpc' library (-lrpc). */
/* #undef HAVE_LIBRPC */

/* Define to 1 if you have the `openat' function. */
/* #undef HAVE_OPENAT */

/* if there's an os-proto.h for this platform, to use additional prototypes */
/* #undef HAVE_OS_PROTO_H */

/* define if libpcap has pcap_debug */
/* #undef HAVE_PCAP_DEBUG */

/* Define to 1 if you have the `pcap_dump_ftell64' function. */
#define HAVE_PCAP_DUMP_FTELL64 1

/* Define to 1 if you have the `pcap_findalldevs_ex' function. */
/* #undef HAVE_PCAP_FINDALLDEVS_EX */

/* Define to 1 if you have the `pcap_open' function. */
/* #undef HAVE_PCAP_OPEN */

/* Define to 1 if you have the <pcap/pcap-inttypes.h> header file. */
#define HAVE_PCAP_PCAP_INTTYPES_H 1

/* Define to 1 if you have the `pcap_set_immediate_mode' function. */
#define HAVE_PCAP_SET_IMMEDIATE_MODE 1

/* Define to 1 if you have the `pcap_set_optimizer_debug' function. */
/* #undef HAVE_PCAP_SET_OPTIMIZER_DEBUG */

/* Define to 1 if you have the `pcap_set_parser_debug' function. */
/* #undef HAVE_PCAP_SET_PARSER_DEBUG */

/* Define to 1 if you have the `pcap_set_tstamp_precision' function. */
#define HAVE_PCAP_SET_TSTAMP_PRECISION 1

/* Define to 1 if you have the `pcap_set_tstamp_type' function. */
#define HAVE_PCAP_SET_TSTAMP_TYPE 1

/* Define to 1 if you have the `pcap_wsockinit' function. */
/* #undef HAVE_PCAP_WSOCKINIT */

/* Define to 1 if you have the <rpc/rpcent.h> header file. */
/* #undef HAVE_RPC_RPCENT_H */

/* Define to 1 if you have the <rpc/rpc.h> header file. */
/* #undef HAVE_RPC_RPC_H */

/* Define to 1 if you have the `strlcat' function. */
/* #undef HAVE_STRLCAT */

/* Define to 1 if you have the `strlcpy' function. */
/* #undef HAVE_STRLCPY */

/* Define to 1 if you have the `strsep' function. */
#define HAVE_STRSEP 1

/* Define to 1 if the system has the type `struct ether_addr'. */
/* #undef HAVE_STRUCT_ETHER_ADDR */

/* Define to 1 if you have the `vfork' function. */
#define HAVE_VFORK 1

/* Define to 1 if you have the `wsockinit' function. */
/* #undef HAVE_WSOCKINIT */

/* define if libpcap has yydebug */
/* #undef HAVE_YYDEBUG */

/* Define to 1 if netinet/ether.h declares `ether_ntohost' */
#define NETINET_ETHER_H_DECLARES_ETHER_NTOHOST 1

/* Define to 1 if netinet/if_ether.h declares `ether_ntohost' */
/* #undef NETINET_IF_ETHER_H_DECLARES_ETHER_NTOHOST */

/* Define to 1 if net/ethernet.h declares `ether_ntohost' */
/* #undef NET_ETHERNET_H_DECLARES_ETHER_NTOHOST */

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "https://github.com/the-tcpdump-group/tcpdump/issues"

/* Define to the full name of this package. */
#define PACKAGE_NAME "tcpdump"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "tcpdump 5.0.0-PRE-GIT"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "tcpdump"

/* Define to the home page for this package. */
#define PACKAGE_URL "https://www.tcpdump.org/"

/* Define to the version of this package. */
#define PACKAGE_VERSION "5.0.0-PRE-GIT"

/* The size of `time_t', as computed by sizeof. */
#define SIZEOF_TIME_T 8

/* The size of `void *', as computed by sizeof. */
#define SIZEOF_VOID_P 8

/* Define to 1 if sys/ethernet.h declares `ether_ntohost' */
/* #undef SYS_ETHERNET_H_DECLARES_ETHER_NTOHOST */

/* define if you have ether_ntohost() and it works */
#define USE_ETHER_NTOHOST 1

/* Define if you enable support for libsmi */
/* #undef USE_LIBSMI */

/* define if should chroot when dropping privileges */
/* #undef WITH_CHROOT */

/* define if should drop privileges by default */
/* #undef WITH_USER */

/* Define to `uint16_t' if u_int16_t not defined. */
/* #undef u_int16_t */

/* Define to `uint32_t' if u_int32_t not defined. */
/* #undef u_int32_t */

/* Define to `uint64_t' if u_int64_t not defined. */
/* #undef u_int64_t */

/* Define to `uint8_t' if u_int8_t not defined. */
/* #undef u_int8_t */

#endif // TCPDUMP_CONFIG_H_
