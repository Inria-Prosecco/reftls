"use strict";

const debug = false;
const stackTrace = require('stack-trace');
const fs = require('fs');
const net = require('net');
const util = require('./util.js');
const tls_crypto = require('./tls_crypto.js');
/* Begin: tls-formats.js - parsing and serializing TLS messages */

var mapError = function (r, f) {
   switch (r.result) {
      case "Correct":
         return Correct(f(r.value));
      case "Error":
         return Incorrect(r.code, r.desc);
      default:
         throw new Error("expected correct or incorrect");
   }
};

var bindError = function (r, f) {
   switch (r.result) {
      case "Correct":
         return f(r.value);
      case "Error":
         return Incorrect(r.code, r.desc);
      default:
         throw new Error("expected correct or incorrect");
   }
};

function Correct(v) {
   return {
      result: "Correct",
      value: v
   };
}

function Incorrect(c, d) {
   return {
      result: "Error",
      code: c,
      desc: d
   };
}

function Pair(x, y) {
   return {
      fst: x,
      snd: y
   };
}

function reverse(o) {
   let no = {};
   for (let e in o) no[o[e]] = e;
   return no;
}
const AD = {
   close_notify: "0100",
   end_of_early_data: "0101",
   unexpected_message: "020a",
   bad_record_mac: "0214",
   decryption_failed: "0215",
   record_overflow: "0216",
   decompression_failure: "021e",
   handshake_failure: "0228",
   no_certificate: "0129",
   bad_certificate_warning: "012a",
   bad_certificate_fatal: "022a",
   unsupported_certificate_warning: "012b",
   unsupported_certificate_fatal: "022b",
   certificate_revoked_warning: "012c",
   certificate_revoked_fatal: "022c",
   certificate_expired_warning: "012d",
   certificate_expired_fatal: "022d",
   certificate_unknown_warning: "012e",
   certificate_unknown_fatal: "022e",
   illegal_parameter: "022f",
   unknown_ca: "0230",
   access_denied: "0231",
   decode_error: "0232",
   decrypt_error: "0233",
   export_restriction: "023c",
   protocol_version: "0246",
   insufficient_security: "0247",
   internal_error: "0250",
   user_cancelled_warning: "015a",
   user_cancelled_fatal: "025a",
   no_renegotiation: "0164",
   unsupported_extension: "026e",
   unrecognized_name: "0270"
};

function lookup(t, i) {
   if (i in t) return t[i];else return i;
}
const AD_rev = reverse(AD);

function AD_lookup(x) {
   return lookup(AD_rev, x);
}
/* Platform.Bytes */
/* TLSConstants */

const PV = {
   SSL_3p0: "0300",
   TLS_1p0: "0301",
   TLS_1p1: "0302",
   TLS_1p2: "0303",
   TLS_1p3: "0304"
};
const PV_rev = reverse(PV);

function PV_lookup(x) {
   return lookup(PV_rev, x);
}

const CM = {
   null_compression: "00",
   deflate: "01"
};
const CM_rev = reverse(CM);

function CM_lookup(x) {
   return lookup(CM_rev, x);
}

const CS = {
   /* RFC5246 Appendix A.5 */
   TLS_NULL_WITH_NULL_NULL: "0000",
   TLS_RSA_WITH_NULL_MD5: "0001",
   TLS_RSA_WITH_NULL_SHA: "0002",
   TLS_RSA_WITH_NULL_SHA256: "003b",
   TLS_RSA_WITH_RC4_128_MD5: "0004",
   TLS_RSA_WITH_RC4_128_SHA: "0005",
   TLS_RSA_WITH_3DES_EDE_CBC_SHA: "000a",
   TLS_RSA_WITH_AES_128_CBC_SHA: "002f",
   TLS_RSA_WITH_AES_256_CBC_SHA: "0035",
   TLS_RSA_WITH_AES_128_CBC_SHA256: "003c",
   TLS_RSA_WITH_AES_256_CBC_SHA256: "003d",
   TLS_DHE_DSS_WITH_DES_CBC_SHA: "0012",
   TLS_DHE_RSA_WITH_DES_CBC_SHA: "0015",
   TLS_DH_DSS_WITH_DES_CBC_SHA: "000c",
   TLS_DH_RSA_WITH_DES_CBC_SHA: "000f",
   TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA: "000d",
   TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA: "0010",
   TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA: "0013",
   TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA: "0016",
   TLS_DH_DSS_WITH_AES_128_CBC_SHA: "0030",
   TLS_DH_RSA_WITH_AES_128_CBC_SHA: "0031",
   TLS_DHE_DSS_WITH_AES_128_CBC_SHA: "0032",
   TLS_DHE_RSA_WITH_AES_128_CBC_SHA: "0033",
   TLS_DH_DSS_WITH_AES_256_CBC_SHA: "0036",
   TLS_DH_RSA_WITH_AES_256_CBC_SHA: "0037",
   TLS_DHE_DSS_WITH_AES_256_CBC_SHA: "0038",
   TLS_DHE_RSA_WITH_AES_256_CBC_SHA: "0039",
   TLS_DH_DSS_WITH_AES_128_CBC_SHA256: "003e",
   TLS_DH_RSA_WITH_AES_128_CBC_SHA256: "003f",
   TLS_DHE_DSS_WITH_AES_128_CBC_SHA256: "0040",
   TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: "0067",
   TLS_DH_DSS_WITH_AES_256_CBC_SHA256: "0068",
   TLS_DH_RSA_WITH_AES_256_CBC_SHA256: "0069",
   TLS_DHE_DSS_WITH_AES_256_CBC_SHA256: "006a",
   TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: "006b",
   TLS_DH_anon_WITH_RC4_128_MD5: "0018",
   TLS_DH_anon_WITH_3DES_EDE_CBC_SHA: "001b",
   TLS_DH_anon_WITH_AES_128_CBC_SHA: "0034",
   TLS_DH_anon_WITH_AES_256_CBC_SHA: "003a",
   TLS_DH_anon_WITH_AES_128_CBC_SHA256: "006c",
   TLS_DH_anon_WITH_AES_256_CBC_SHA256: "006d",
   /* RFC4492 Section 6 */
   TLS_ECDH_ECDSA_WITH_NULL_SHA: "c001",
   TLS_ECDH_ECDSA_WITH_RC4_128_SHA: "c001",
   TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA: "c003",
   TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA: "c004",
   TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA: "c005",
   TLS_ECDHE_ECDSA_WITH_NULL_SHA: "c006",
   TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: "c007",
   TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA: "c008",
   TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: "c009",
   TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: "c00a",
   TLS_ECDH_RSA_WITH_NULL_SHA: "c00b",
   TLS_ECDH_RSA_WITH_RC4_128_SHA: "c00c",
   TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA: "c00d",
   TLS_ECDH_RSA_WITH_AES_128_CBC_SHA: "c00e",
   TLS_ECDH_RSA_WITH_AES_256_CBC_SHA: "c00f",
   TLS_ECDHE_RSA_WITH_NULL_SHA: "c010",
   TLS_ECDHE_RSA_WITH_RC4_128_SHA: "c011",
   TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: "c012",
   TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: "c013",
   TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: "c014",
   TLS_ECDH_anon_WITH_NULL_SHA: "c015",
   TLS_ECDH_anon_WITH_RC4_128_SHA: "c016",
   TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA: "c017",
   TLS_ECDH_anon_WITH_AES_128_CBC_SHA: "c018",
   TLS_ECDH_anon_WITH_AES_256_CBC_SHA: "c019",
   /* RFC5289 Section 3 */
   TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: "c023",
   TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: "c024",
   TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256: "c025",
   TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384: "c026",
   TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: "c027",
   TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: "c028",
   TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256: "c029",
   TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384: "c02a",
   TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "c02b",
   TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "c02c",
   TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256: "c02d",
   TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384: "c02e",
   TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: "c02f",
   TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: "c030",
   TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256: "c031",
   TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384: "c032",
   /* RFC5288 Section 3 */
   TLS_RSA_WITH_AES_128_GCM_SHA256: "009c",
   TLS_RSA_WITH_AES_256_GCM_SHA384: "009d",
   TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: "009e",
   TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: "009f",
   TLS_DH_RSA_WITH_AES_128_GCM_SHA256: "00a0",
   TLS_DH_RSA_WITH_AES_256_GCM_SHA384: "00a1",
   TLS_DHE_DSS_WITH_AES_128_GCM_SHA256: "00a2",
   TLS_DHE_DSS_WITH_AES_256_GCM_SHA384: "00a3",
   TLS_DH_DSS_WITH_AES_128_GCM_SHA256: "00a4",
   TLS_DH_DSS_WITH_AES_256_GCM_SHA384: "00a5",
   TLS_DH_anon_WITH_AES_128_GCM_SHA256: "00a6",
   TLS_DH_anon_WITH_AES_256_GCM_SHA384: "00a7",
   /* RFC 4279 */
   TLS_PSK_WITH_AES_128_GCM_SHA256: "00a8",
   TLS_DHE_PSK_WITH_AES_128_GCM_SHA256: "00aa",
   TLS_PSK_WITH_AES_128_CBC_SHA256: "00ae",
   /* Unknown Draft */
   TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256: "d001",
   /* RFC 5746 */
   TLS_EMPTY_RENEGOTIATION_INFO_SCSV: "00ff",
   /* RFC 7507 */
   TLS_FALLBACK_SCSV: "5600",
   /* Chrome - unknown rfc */
   ECDHE_RSA_CHACHA20_POLY1305: "cc13",
   ECDHE_ECDSA_CHACHA20_POLY1305: "cc14",
   DHE_RSA_CHACHA20_POLY1305: "cc15",
   /* TLS 1.3 A.4 */
   TLS_AES_128_GCM_SHA256: "1301",
   TLS_AES_256_GCM_SHA384: "1302",
   TLS_CHACHA20_POLY1305_SHA256: "1303",
   TLS_AES_128_CCM_SHA256: "1304",
   TLS_AES_128_CCM_8_SHA256: "1305"
};

const CS_rev = reverse(CS);

function CS_lookup(x) {
   return lookup(CS_rev, x);
}

function KEX(x) {
   const c = CS_lookup(x);
   if (c === "TLS_AES_128_GCM_SHA256") return "ECDHE";
   if (c.startsWith("TLS_RSA_")) return "RSA";else if (c.startsWith("TLS_DHE_")) return "DHE";else if (c.startsWith("TLS_ECDHE_")) return "ECDHE";else throw "server chose non-RSA/DHE/ECDHE ciphersuite";
}

function AE(pv, x) {
   const c = CS_lookup(x);
   if (c.endsWith("AES_128_GCM_SHA256") && pv == PV.TLS_1p3) {
      return "AES_128_GCM_SHA256_TLS13";
   }
   if (c.endsWith("WITH_AES_128_GCM_SHA256")) {
      return "AES_128_GCM_SHA256";
   } else if (c.endsWith("WITH_AES_128_CBC_SHA") && pv == PV.TLS_1p0) {
      return "AES_128_CBC_SHA_Stale";
   } else if (c.endsWith("WITH_AES_128_CBC_SHA")) {
      return "AES_128_CBC_SHA_Fresh";
   } else {
      throw "server chose non AES_128_GCM/CBC ciphersuite";
   }
}

function vlbytes(n, data) {
   //        console.log("data.length="+data.length+",d="+data);
   const l = util.getLength(data);
   const lb = util.bytes_of_int(l, n);
   return lb + data;
}

function vlsplit(n, data) {
   //console.log("splitting n:"+n+",d:"+data);
   const sp = util.split(data, n);
   const l = util.int_of_bytes(sp.fst, n);
   if (l <= util.getLength(sp.snd)) return Correct(util.split(sp.snd, l));else return Incorrect(AD.decode_error, "vlsplit n:" + n + ",l:" + l + ",d:" + data + "\n" + stackTrace.get());
}

function vlparse(n, data) {
   //console.log("splitting n:"+n+",d:"+data);
   const sp = util.split(data, n);
   const l = util.int_of_bytes(sp.fst, n);
   if (l == util.getLength(sp.snd)) return Correct(sp.snd);else return Incorrect(AD.decode_error, "vlparse n:" + n + ",l:" + l + ",d.length" + data.length + "\n" + stackTrace.get().join("\n"));
}
/* HandshakeMessages */

const HT = {
   hello_request: "00",
   client_hello: "01",
   server_hello: "02",
   certificate: "0b",
   server_key_exchange: "0c",
   certificate_request: "0d",
   server_hello_done: "0e",
   certificate_verify: "0f",
   client_key_exchange: "10",
   finished: "14",
   encrypted_extensions: "08",
   session_ticket: "04"
};
const HT_rev = reverse(HT);

function HT_lookup(x) {
   return lookup(HT_rev, x);
}

function messageBytes(ht, data) {
   return ht + vlbytes(3, data);
}

function parseMessage(buf) {
   if (util.getLength(buf) < 4) return Correct(Pair(undefined, buf));else {
      const hp = util.split(buf, 1);
      return mapError(vlsplit(3, hp.snd), pr => {
         const to_log = messageBytes(hp.fst, pr.fst);
         return Pair({ ht: hp.fst,
            pl: pr.fst,
            to_log: to_log
         }, pr.snd);
      });
   }
}

const EXT = {
   renegotiation_info: "ff01",
   server_name: "0000",
   max_fragment_length: "0001",
   client_certificate_url: "0002",
   trusted_ca_keys: "0003",
   truncated_hmac: "0004",
   status_request: "0005",
   extended_ms: "0017",
   extended_padding: "008f",
   ec_point_format: "000b",
   //ec_curves: "000a",
   supported_groups: "000a",
   srp: "000c",
   signature_algorithms: "000d",
   session_ticket: "0023",
   heartbeat: "000f",
   next_protocol_negotiation: "3374",
   application_layer_protocol_negotiation: "0010",
   key_share: "0028",
   pre_shared_key: "0029",
   early_data: "002a",
   supported_versions: "002b",
   cookie: "002c",
   psk_key_exchange_modes: "002d",
   ticket_early_data_info: "002e"
};
const EXT_rev = reverse(EXT);

function EXT_lookup(x) {
   return lookup(EXT_rev, x);
}

const HA = {
   none: "00",
   md5: "01",
   sha1: "02",
   sha224: "03",
   sha256: "04",
   sha384: "05",
   sha512: "06"
};
const HA_rev = reverse(HA);

function HA_lookup(x) {
   return lookup(HA_rev, x);
}

const SA = {
   anonymous: "00",
   rsa: "01",
   dsa: "02",
   ecdsa: "03",
   rsapss: "04",
   eddsa: "05"
};
const SA_rev = reverse(SA);
function SA_lookup(x) {
   return lookup(SA_rev, x);
}

/* Signature scheme in TLS 1.3 */
const SS = {
   rsa_pkcs1_md5: "0101",
   rsa_pkcs1_sha1: "0201",
   rsa_pkcs1_sha256: "0401",
   rsa_pkcs1_sha384: "0501",
   rsa_pkcs1_sha512: "0601",

   dsa_sha1: "0202",

   ecdsa_secp256r1_sha256: "0403",
   ecdsa_secp384r1_sha384: "0503",
   ecdsa_secp521r1_sha512: "0603",

   rsa_pss_sha256: "0804",
   rsa_pss_sha384: "0805",
   rsa_pss_sha512: "0806",

   ed25519: "0807",
   ed448: "0808"
};
const SS_rev = reverse(SS);
function SS_lookup(x) {
   return lookup(SS_rev, x);
}

const SG = {
   sect163k1: "0001",
   sect163r1: "0002",
   sect163r2: "0003",
   sect193r1: "0004",
   sect193r2: "0005",
   sect233k1: "0006",
   sect233r1: "0007",
   sect239k1: "0008",
   sect283k1: "0009",
   sect283r1: "000a",
   sect409k1: "000b",
   sect409r1: "000c",
   sect571k1: "000d",
   sect571r1: "000e",
   secp160k1: "000f",
   secp160r1: "0010",
   secp160r2: "0011",
   secp192k1: "0012",
   secp192r1: "0013",
   secp224k1: "0014",
   secp224r1: "0015",
   secp256k1: "0016",
   secp256r1: "0017",
   secp384r1: "0018",
   secp521r1: "0019",
   brainpoolP256r1: "001a",
   brainpoolP384r1: "001b",
   brainpoolP512r1: "001c",
   arbitrary_explicit_prime_curves: "FF01",
   arbitrary_explicit_char2_curves: "FF02",
   ffdhe2048: "0100",
   ffdhe3072: "0101",
   ffdhe4096: "0102",
   ffdhe6144: "0103",
   ffdhe8192: "0104"
};
const SG_rev = reverse(SG);

function SG_lookup(x) {
   return lookup(SG_rev, x);
}

function isEC(g) {
   switch (g) {
      case SG.sect163k1:
      case SG.sect163r1:
      case SG.sect163r2:
      case SG.sect193r1:
      case SG.sect193r2:
      case SG.sect233k1:
      case SG.sect233r1:
      case SG.sect239k1:
      case SG.sect283k1:
      case SG.sect283r1:
      case SG.sect409k1:
      case SG.sect409r1:
      case SG.sect571k1:
      case SG.sect571r1:
      case SG.secp160k1:
      case SG.secp160r1:
      case SG.secp160r2:
      case SG.secp192k1:
      case SG.secp192r1:
      case SG.secp224k1:
      case SG.secp224r1:
      case SG.secp256k1:
      case SG.secp256r1:
      case SG.secp384r1:
      case SG.secp521r1:
      case SG.brainpoolP256r1:
      case SG.brainpoolP384r1:
      case SG.brainpoolP512r1:
      case SG.arbitrary_explicit_prime_curves:
      case SG.arbitrary_explicit_char2_curves:
         //	console.log("ec");
         return true;
      default:
         return false;
   }
}

const PF = {
   uncompressed: "00",
   ansiX962_compressed_prime: "01",
   ansiX962_compressed_char2: "02"
};
const PF_rev = reverse(PF);

function PF_lookup(x) {
   return lookup(PF_rev, x);
}

const CT = {
   rsa_sign: "01",
   dss_sign: "02",
   rsa_fixed_dh: "03",
   dss_fixed_dh: "04",
   rsa_ephemeral_dh_RESERVED: "05",
   dss_ephemeral_dh_RESERVED: "06",
   fortezza_dms_RESERVED: "14",
   ecdsa_sign: "40",
   rsa_fixed_ecdh: "41",
   ecdsa_fixed_ecdh: "42"
};
const CT_rev = reverse(CT);

function CT_lookup(x) {
   return lookup(CT_rev, x);
}

function clientExtensionBytes(ext_type, ext_data) {
   switch (ext_type) {
      case EXT.renegotiation_info:
         return ext_type + vlbytes(2, vlbytes(1, ext_data.client_verify_data));
      case EXT.server_name:
         return ext_type + vlbytes(2, vlbytes(2, ext_data.map(d => d.name_type + vlbytes(2, d.host_name)).join("")));
      case EXT.signature_algorithms:
         return ext_type + vlbytes(2, vlbytes(2, ext_data.join("")));
      case EXT.supported_groups:
         return ext_type + vlbytes(2, vlbytes(2, ext_data.join("")));
      case EXT.supported_versions:
         return ext_type + vlbytes(2, vlbytes(1, ext_data.join("")));
      case EXT.ec_point_format:
         return ext_type + vlbytes(2, vlbytes(1, ext_data.join("")));
      case EXT.application_layer_protocol_negotiation:
         return ext_type + vlbytes(2, vlbytes(2, ext_data.map(d => vlbytes(1, d)).join("")));
      case EXT.next_protocol_negotiation:
         return ext_type + vlbytes(2, ext_data.map(d => vlbytes(1, d)).join(""));
      //    case EXT.tls13_draft_version:
      //	return ext_type + vlbytes(2, ext_data)

      case EXT.key_share:
         return ext_type + vlbytes(2, vlbytes(2, ext_data.map(d => {
            return d.dh_group + vlbytes(2, d.dh_public);
         }).join("")));

      case EXT.pre_shared_key:
         return ext_type + vlbytes(2, vlbytes(2, ext_data.map(d => {
            return vlbytes(2, d.psk_identity) + d.obfuscated_ticket_age;
         }).join("")));
      // TODO: Add PSK Binder
      case EXT.psk_key_exchange_modes:
         return ext_type + vlbytes(2, vlbytes(1, ext_data.join("")));

      case EXT.early_data:
         return ext_type + vlbytes(2, "");
      default:
         return ext_type + vlbytes(2, ext_data);
   }
}

function serverExtensionBytes(ext_type, ext_data) {
   switch (ext_type) {
      case EXT.renegotiation_info:
         return ext_type + vlbytes(2, vlbytes(1, ext_data.client_server_verify_data));
      case EXT.ec_point_format:
         return ext_type + vlbytes(2, vlbytes(1, ext_data.join("")));
      case EXT.next_protocol_negotiation:
         return ext_type + vlbytes(2, ext_data.map((d, i) => vlbytes(1, d)).join(""));
      case EXT.key_share:
         return ext_type + vlbytes(2, ext_data.dh_group + vlbytes(2, ext_data.dh_public));
      case EXT.pre_shared_key:
         return ext_type + vlbytes(2, vlbytes(2, ext_data.psk_identity));
      case EXT.early_data:
         return ext_type + vlbytes(2, "");
      default:
         return ext_type + vlbytes(2, ext_data);
   }
}

function extensionsBytes(exts, f) {
   let res = util.empty_bytes;
   for (let e in exts) {
      //console.log("res_len:"+res.length+",ext_n:"+e+",ext_d:"+exts[e]);
      res += f(e, exts[e]);
   }
   if (util.getLength(res) == 0) return util.empty_bytes;else return vlbytes(2, res);
}

function parseServerNames(b) {
   return bindError(vlparse(2, b), snl => {
      const sn = [];
      while (util.getLength(snl) > 0) {
         const sp1 = util.split(snl, 1);
         const sp2 = vlsplit(2, sp1.snd);
         let res = sp2;
         switch (res.result) {
            case "Error":
               return Incorrect(res.code, res.desc);
            case "Correct":
               sn.push({
                  name_type: sp1.fst,
                  host_name: res.value.fst
               });
               snl = res.value.snd;
               break;
            default:
               throw "getResult returned non-Result" + new Error().stack;
         }
      }
      return Correct(sn);
   });
}

function parseProtocolNames(b) {
   return bindError(vlparse(2, b), pnl => {
      const pn = [];
      while (util.getLength(pnl) > 0) {
         const sp = vlsplit(1, pnl);
         let res = sp;
         switch (res.result) {
            case "Error":
               return Incorrect(res.code, res.desc);
            case "Correct":
               pn.push(res.value.fst);
               pnl = res.value.snd;
               break;
            default:
               throw "getResult returned non-Result" + new Error().stack;
         }
      }
      return Correct(pn);
   });
}

function parseNextProtocolNames(pnl) {
   const pn = [];
   while (util.getLength(pnl) > 0) {
      const sp = vlsplit(1, pnl);
      let res = sp;
      switch (res.result) {
         case "Error":
            return Incorrect(res.code, res.desc);
         case "Correct":
            pn.push(res.value.fst);
            pnl = res.value.snd;
            break;
         default:
            throw "getResult returned non-Result" + new Error().stack;
      }
   }
   return Correct(pn);
}

function parseSignatureAlgorithmsList(b) {
   if (b.length % 4 != 0) return Incorrect(AD.decode_error, "parseSignatureAlgorithmsList: not a multiple of 4");
   const sa = [];
   for (let i = 0; i < b.length; i = i + 4) sa.push(b.substring(i, i + 4));
   return Correct(sa);
}

function parseSignatureAlgorithms(b) {
   return bindError(vlparse(2, b), parseSignatureAlgorithmsList);
}

function parseSupportedGroups(b) {
   return bindError(vlparse(2, b), b => {
      let res;
      if (b.length % 4 != 0) res = Incorrect(AD.decode_error, "parseSupportedGroups: not a multiple of 4");else {
         const ec = [];
         for (let i = 0; i < b.length; i = i + 4) ec.push(b.substring(i, i + 4));
         res = Correct(ec);
      }
      return res;
   });
}

function parseSupportedVersions(b) {
   return bindError(vlparse(1, b), b => {
      let res;
      if (b.length % 4 != 0) res = Incorrect(AD.decode_error, "parseSupportedVersions: not a multiple of 4");else {
         const pv = [];
         for (let i = 0; i < b.length; i = i + 4) pv.push(b.substring(i, i + 4));
         res = Correct(pv);
      }
      return res;
   });
}

function parseKeyShares(b) {
   return bindError(vlparse(2, b), b => {
      const ks = [];
      let curr = b;
      while (util.getLength(curr) > 0) {
         const sp1 = util.split(curr, 2);
         let dhg = sp1.fst;
         const sp2 = vlsplit(2, sp1.snd);
         let res = sp2;
         switch (res.result) {
            case "Error":
               return Incorrect(res.code, res.desc);
            case "Correct":
               ks.push({
                  dh_group: dhg,
                  dh_public: res.value.fst
               });
               curr = res.value.snd;
         }
      }
      return Correct(ks);
   });
}

function parsePSKIdentities(b) {
   //    console.log("PSK Identities:" + b);
   return bindError(vlparse(2, b), b => {
      const ks = [];
      let curr = b;
      while (util.getLength(curr) > 0) {
         const sp = vlsplit(2, curr);
         let res = sp;
         switch (res.result) {
            case "Error":
               return Incorrect(res.code, res.desc);
            case "Correct":
               {
                  if (util.getLength(res.value.snd) < 4) return Incorrect(AD.decode_error, "missing obfuscated_ticket_age");
                  let x = util.split(res.value.snd, 4);
                  ks.push({
                     psk_identity: res.value.fst,
                     obfuscated_ticket_age: x.fst
                  });
                  curr = x.snd;
               }
         }
      }
      return Correct(ks);
   });
}

function parseKeyShare(b) {
   const sp1 = util.split(b, 2);
   let dhg = sp1.fst;
   return mapError(vlparse(2, sp1.snd), b => {
      return {
         dh_group: dhg,
         dh_public: b
      };
   });
}

function parsePSKIdentity(b) {
   //    console.log(b);
   return mapError(vlparse(2, b), b => {
      //	console.log(b);
      return {
         psk_identity: b
      };
   });
}

function parsePointFormats(b) {
   return mapError(vlparse(1, b), b => {
      const pf = [];
      for (let i = 0; i < b.length; i = i + 2) pf.push(b.substring(i, i + 2));
      return pf;
   });
}

function parseCertificateTypes(b) {
   const cts = [];
   for (let i = 0; i < b.length; i = i + 2) cts.push(b.substring(i, i + 2));
   return cts;
}

function parseDistinguishedNames(dnl) {
   const dn = [];
   while (util.getLength(dnl) > 0) {
      const sp = vlsplit(2, dnl);
      let res = sp;
      switch (res.result) {
         case "Error":
            return Incorrect(res.code, res.desc);
         case "Correct":
            dn.push(res.value.fst);
            break;
         default:
            throw "getResult returned non-Result" + new Error().stack;
      }
      dnl = res.value.snd;
   }
   return Correct(dn);
}

function parseClientExtension(b) {
   if (util.getLength(b) < 4) return Incorrect(AD.decode_error, "clientExtension has less than 4 bytes");else {
      const sp = util.split(b, 2);
      return bindError(vlsplit(2, sp.snd), d => {
         switch (sp.fst) {
            case EXT.renegotiation_info:
               return mapError(vlparse(1, d.fst), cvd => Pair({
                  extension_type: sp.fst,
                  extension_data: {
                     client_verify_data: cvd
                  }
               }, d.snd));
            case EXT.server_name:
               return mapError(parseServerNames(d.fst), snl => Pair({
                  extension_type: sp.fst,
                  extension_data: snl
               }, d.snd));
            case EXT.signature_algorithms:
               return mapError(parseSignatureAlgorithms(d.fst), sal => Pair({
                  extension_type: sp.fst,
                  extension_data: sal
               }, d.snd));
            case EXT.supported_groups:
               return mapError(parseSupportedGroups(d.fst), ecl => Pair({
                  extension_type: sp.fst,
                  extension_data: ecl
               }, d.snd));
            case EXT.supported_versions:
               return mapError(parseSupportedVersions(d.fst), ecl => Pair({
                  extension_type: sp.fst,
                  extension_data: ecl
               }, d.snd));
            case EXT.ec_point_format:
               return mapError(parsePointFormats(d.fst), pfl => Pair({
                  extension_type: sp.fst,
                  extension_data: pfl
               }, d.snd));
            case EXT.application_layer_protocol_negotiation:
               return mapError(parseProtocolNames(d.fst), pnl => Pair({
                  extension_type: sp.fst,
                  extension_data: pnl
               }, d.snd));
            case EXT.next_protocol_negotiation:
               if (util.getLength(d.fst) != 0) return Incorrect(AD.decode_error, "clienthello must contain empty NPN");else return Correct(Pair({
                  extension_type: sp.fst,
                  extension_data: []
               }, d.snd));
            //	    case EXT.tls13_draft_version:
            //		if (util.getLength(d.fst) != 2) return Incorrect(AD.decode_error,
            //								 "clienthello tls13 draft version must 2 bytes")
            //		return Correct(Pair({
            //		    extension_type: sp.fst,
            //		    extension_data: d.fst
            //		}, d.snd))
            case EXT.key_share:
               return mapError(parseKeyShares(d.fst), pfl => Pair({
                  extension_type: sp.fst,
                  extension_data: pfl
               }, d.snd));
            case EXT.pre_shared_key:
               // TODO: Add PSK Binder
               return mapError(parsePSKIdentities(d.fst), pfl => Pair({
                  extension_type: sp.fst,
                  extension_data: pfl
               }, d.snd));
            default:
               //TODO: EalyDataIndication
               return Correct(Pair({
                  extension_type: sp.fst,
                  extension_data: d.fst
               }, d.snd));
         }
      });
   }
}

function parseServerExtension(b) {
   if (util.getLength(b) < 4) return Incorrect(AD.decode_error, "serverExtension has less than 4 bytes");else {
      const sp = util.split(b, 2);
      return bindError(vlsplit(2, sp.snd), d => {
         switch (sp.fst) {
            case EXT.renegotiation_info:
               return mapError(vlparse(1, d.fst), cvd => Pair({
                  extension_type: sp.fst,
                  extension_data: {
                     client_server_verify_data: cvd
                  }
               }, d.snd));
            case EXT.ec_point_format:
               return mapError(parsePointFormats(d.fst), pfl => Pair({
                  extension_type: sp.fst,
                  extension_data: pfl
               }, d.snd));
            case EXT.key_share:
               return mapError(parseKeyShare(d.fst), ks => Pair({
                  extension_type: sp.fst,
                  extension_data: ks
               }, d.snd));

            case EXT.pre_shared_key:
               return mapError(parsePSKIdentity(d.fst), ks => Pair({
                  extension_type: sp.fst,
                  extension_data: ks
               }, d.snd));

            case EXT.application_layer_protocol_negotiation:
               return bindError(parseProtocolNames(d.fst), pnl => {
                  if (pnl.length > 1) return Incorrect(AD.decode_error, "serverHello alpn extension not singleton");else return Correct(Pair({
                     extension_type: sp.fst,
                     extension_data: pnl
                  }, d.snd));
               });
            case EXT.next_protocol_negotiation:
               return mapError(parseNextProtocolNames(d.fst), pnl => Pair({
                  extension_type: sp.fst,
                  extension_data: pnl
               }, d.snd));
            case EXT.server_name:
               if (util.getLength(d.fst) != 0) return Incorrect(AD.decode_error, "serverHello server_name extension not empty");else return Correct(Pair({
                  extension_type: sp.fst,
                  extension_data: []
               }, d.snd));
            default:
               return Correct(Pair({
                  extension_type: sp.fst,
                  extension_data: d.fst
               }, d.snd));
         }
      });
   }
}

function parseExtensions(b, f) {
   if (util.getLength(b) == 0) return Correct({});else {
      return bindError(vlparse(2, b), extb => {
         const exts = {};
         while (util.getLength(extb) > 0) {
            //console.log("extb:"+extb);
            const ce = f(extb);
            let res = ce;
            switch (res.result) {
               case "Correct":
                  exts[res.value.fst.extension_type] = res.value.fst.extension_data;
                  extb = res.value.snd;
                  break;
               case "Error":
                  return Incorrect(res.code, res.desc);
               default:
                  throw "parseExtension returned non-Result" + new Error().stack;
            }
            //console.log("extb':"+extb);
         }
         return Correct(exts);
      });
   }
}

function cipherSuitesBytes(cs) {
   return cs.join("");
}

function parseCipherSuites(b) {
   if (b.length % 4 != 0) return Incorrect(AD.decode_error, "parseCipherSuites: not a multiple of 4");
   const cs = [];
   for (let i = 0; i < b.length; i = i + 4) cs.push(b.substring(i, i + 4));
   return Correct(cs);
}

function compressionsBytes(cms) {
   return cms.join("");
}

function parseCompressions(b) {
   if (b.length % 2 != 0) return Incorrect(AD.decode_error, "parseCompressions: not a multiple of 4");
   const cs = [];
   for (let i = 0; i < b.length; i = i + 2) cs.push(b.substring(i, i + 2));
   return Correct(cs);
}

const fullClientHello = function () {
   const ch = {
      protocol_version: PV.TLS_1p2,
      client_random: util.zeroes(64),
      sessionID: "",
      cipher_suites: Object.keys(CS).map(k => CS[k]),
      compressions: Object.keys(CM).map(k => CM[k]),
      extensions: {}
   };
   ch.extensions[EXT.renegotiation_info] = {
      client_verify_data: ""
   };
   ch.extensions[EXT.server_name] = [{
      name_type: "00",
      host_name: util.a2hex("localhost")
   }];
   ch.extensions[EXT.signature_algorithms] = Object.keys(SS).map(k => SS[k]);
   ch.extensions[EXT.supported_groups] = Object.keys(SG).map(k => SG[k]);
   ch.extensions[EXT.supported_versions] = Object.keys(PV).map(k => PV[k]);
   ch.extensions[EXT.ec_point_format] = Object.keys(PF).map(k => PF[k]);
   ch.extensions[EXT.application_layer_protocol_negotiation] = [util.a2hex("http/1.1"), util.a2hex("spdy/1"), util.a2hex("spdy/2"), util.a2hex("spdy/3")];
   ch.extensions[EXT.next_protocol_negotiation] = [];
   return ch;
}();

const defaultClientHello = function (cfg, cr, keys) {
   const ch = {
      protocol_version: cfg.ver_max,
      client_random: cr,
      sessionID: "",
      cipher_suites: cfg.cipher_suites,
      compressions: cfg.compressions,
      extensions: {}
   };
   ch.extensions[EXT.renegotiation_info] = {
      client_verify_data: ""
   };
   ch.extensions[EXT.signature_algorithms] = cfg.sigalgs;
   ch.extensions[EXT.supported_groups] = cfg.groups;
   let versions = [];
   if (cfg.ver_max == PV.TLS_1p3) {
      ch.protocol_version = PV.TLS_1p2;
      versions.push("0303");
      versions.push("7f14");
      versions.push("0304");
   } else versions.push(cfg.ver_max);
   if (cfg.ver_max !== cfg.ver_min) versions.push(cfg.ver_min);
   ch.extensions[EXT.supported_versions] = versions;
   ch.extensions[EXT.ec_point_format] = [PF.uncompressed];
   ch.extensions[EXT.application_layer_protocol_negotiation] = [util.a2hex("http/1.1")];
   //    ch.extensions[EXT.session_ticket] = "";
   //    ch.extensions[EXT.tls13_draft_version] = "000d";
   ch.extensions[EXT.key_share] = [{
      dh_group: SG.secp256r1,
      dh_public: keys.p256
   }, {
      dh_group: SG.ffdhe2048,
      dh_public: keys.ff2048
   }];
   return ch;
};

function clientHelloBytes(ch) {
   const data = ch.protocol_version + ch.client_random + vlbytes(1, ch.sessionID) + vlbytes(2, cipherSuitesBytes(ch.cipher_suites)) + vlbytes(1, compressionsBytes(ch.compressions)) + extensionsBytes(ch.extensions, clientExtensionBytes);
   return messageBytes(HT.client_hello, data);
}

function parseClientHello(d) {
   if (util.getLength(d) < 34) return Incorrect(AD.decode_error, "clientHello less than 34 bytes");else {
      const sp1 = util.split(d, 2);
      const pv = sp1.fst;
      const sp2 = util.split(sp1.snd, 32);
      const cr = sp2.fst;
      if (util.getLength(sp2.snd) < 1) return Incorrect(AD.decode_error, "clientHello: no session id");else {
         return bindError(vlsplit(1, sp2.snd), sp3 => {
            if (util.getLength(sp3.fst) > 32) return Incorrect(AD.decode_error, "clientHello: session id more than 32 bytes");else {
               const sid = sp3.fst;
               if (util.getLength(sp3.snd) < 2) return Incorrect(AD.decode_error, "clientHello: no ciphersuites");else {
                  return bindError(vlsplit(2, sp3.snd), sp4 => bindError(parseCipherSuites(sp4.fst), cs => {
                     if (util.getLength(sp4.snd) < 1) return Incorrect(AD.decode_error, "clientHello: no compressions");else {
                        return bindError(vlsplit(1, sp4.snd), sp5 => bindError(parseCompressions(sp5.fst), cm => mapError(parseExtensions(sp5.snd, parseClientExtension), exts => ({
                           protocol_version: pv,
                           client_random: cr,
                           sessionID: sid,
                           cipher_suites: cs,
                           compressions: cm,
                           extensions: exts
                        }))));
                     }
                  }));
               }
            }
         });
      }
   }
}

const defaultServerHello = function (sr) {
   const sh = {
      protocol_version: PV.TLS_1p2,
      server_random: sr,
      sessionID: "",
      cipher_suite: CS.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      compression: CM.null_compression,
      extensions: {}
   };
   sh.extensions[EXT.renegotiation_info] = {
      client_server_verify_data: ""
   };
   sh.extensions[EXT.ec_point_format] = [PF.uncompressed];
   //sh.extensions.next_protocol_negotiation = [util.a2hex("http/1.1"), util.a2hex(
   //    "spdy/1"), util.a2hex("spdy/2"), util.a2hex("spdy/3")];
   return sh;
};

function serverHelloBytes(sh) {
   var data;
   console.log(sh);
   if (sh.protocol_version == PV.TLS_1p3 || sh.protocol_version == "7f14") {
      sh.protocol_version = "7f14";
      let exts = extensionsBytes(sh.extensions, serverExtensionBytes);
      console.log(exts);
      data = sh.protocol_version + sh.server_random + sh.cipher_suite + exts;
   } else data = sh.protocol_version + sh.server_random + vlbytes(1, sh.sessionID) + sh.cipher_suite + sh.compression + extensionsBytes(sh.extensions, serverExtensionBytes);
   return messageBytes(HT.server_hello, data);
}

function parseServerHello(d) {
   if (util.getLength(d) < 34) return Incorrect(AD.decode_error, "serverHello: less than 34 bytes");else {
      const sp1 = util.split(d, 2);
      const pv = sp1.fst;
      const sp2 = util.split(sp1.snd, 32);
      const sr = sp2.fst;
      var sid = "";
      var cm = "";
      if (util.getLength(sp2.snd) < 1) return Incorrect(AD.decode_error, "serverHello: no ciphersuite");else {
         var rem = sp2.snd;
         if (pv != PV.TLS_1p3 && pv != "7f14") {
            const sp3 = vlsplit(1, sp2.snd);
            let res = sp3;
            switch (res.result) {
               case "Error":
                  return Incorrect(AD.decode_error, "serverHello: no session id");
               case "Correct":
                  if (util.getLength(res.value.fst) > 32) return Incorrect(AD.decode_error, "serverHello: session id too large");else {
                     sid = res.value.fst;
                     rem = res.value.snd;
                     break;
                  }
               default:
                  throw "getResult returned non-Result" + new Error().stack;
            }
         }
         if (util.getLength(rem) < 2) {
            return Incorrect(AD.decode_error, "severHello: no ciphersuite,compression");
         } else {
            const sp4 = util.split(rem, 2);
            const cs = sp4.fst;
            rem = sp4.snd;
            if (pv != PV.TLS_1p3 && pv != "7f14") {
               const sp5 = util.split(sp4.snd, 1);
               cm = sp5.fst;
               rem = sp5.snd;
            }
            return mapError(parseExtensions(rem, parseServerExtension), exts => ({
               protocol_version: pv,
               server_random: sr,
               sessionID: sid,
               cipher_suite: cs,
               compression: cm,
               extensions: exts
            }));
         }
      }
   }
}

const defaultServerCertificate = {
   chain: [tls_crypto.server_cert.hex]
};

function certificateBytes(c, pv) {
   if (pv === PV.TLS_1p3) {
      let cb = util.empty_bytes;
      for (let i = 0; i < c.chain.length; i++) cb += vlbytes(3, c.chain[i]) + vlbytes(2, "");
      return messageBytes(HT.certificate, vlbytes(1, util.empty_bytes) + vlbytes(3, cb));
   } else {
      let cb = util.empty_bytes;
      for (let i = 0; i < c.chain.length; i++) cb += vlbytes(3, c.chain[i]);
      return messageBytes(HT.certificate, vlbytes(3, cb));
   }
}

function parseCertificate(b, pv, from_server) {
   if (pv === PV.TLS_1p3) {
      return bindError(vlsplit(1, b), xx => {
         return bindError(vlparse(3, xx.snd), clb => {
            const ch = [];
            while (util.getLength(clb) > 0) {
               const sp = vlsplit(3, clb);
               let res = sp;
               switch (res.result) {
                  case "Error":
                     return Incorrect(res.code, res.desc);
                  case "Correct":
                     ch.push(res.value.fst);

                     break;
                  default:
                     throw "getResult returned non-Result" + new Error().stack;
               }
               let sp2 = vlsplit(2, res.value.snd);
               switch (sp2.result) {
                  case "Error":
                     return Incorrect(sp2.code, sp2.desc);
                  case "Correct":
                     clb = sp2.value.snd;
                     break;
                  default:
                     throw "getResult returned non-Result" + new Error().stack;
               }
            }
            return Correct({
               chain: ch
            });
         });
      });
   } else return bindError(vlparse(3, b), clb => {
      const ch = [];
      while (util.getLength(clb) > 0) {
         const sp = vlsplit(3, clb);
         let res = sp;
         switch (res.result) {
            case "Error":
               return Incorrect(res.code, res.desc);
            case "Correct":
               ch.push(res.value.fst);
               clb = res.value.snd;
               break;
            default:
               throw "getResult returned non-Result" + new Error().stack;
         }
      }
      return Correct({
         chain: ch
      });
   });
}

const defaultCertificateRequest = {
   certificate_types: Object.keys(CT).map(k => CT[k]),
   signature_algorithms: Object.keys(SS).map(k => SS[k]),
   distinguished_names: []
};

function certificateRequestBytes(scr, pv) {
   const ctl = vlbytes(1, scr.certificate_types.join(""));
   const sal = pv == PV.TLS_1p2 ? vlbytes(2, scr.signature_algorithms.join("")) : util.empty_bytes;
   const dnl = vlbytes(2, scr.distinguished_names.map(h => vlbytes(2, h)).join(""));
   const data = ctl + sal + dnl;
   return messageBytes(HT.certificate_request, data);
}

function parseCertificateRequest(b, pv) {
   return bindError(vlsplit(1, b), sp => {
      const ctl = parseCertificateTypes(sp.fst);
      if (pv == PV.TLS_1p2) {
         return bindError(vlsplit(2, sp.snd), sp2 => bindError(parseSignatureAlgorithmsList(sp2.fst), sal => bindError(vlparse(2, sp2.snd), dnb => mapError(parseDistinguishedNames(dnb), dns => ({
            certificate_types: ctl,
            signature_algorithms: sal,
            distinguished_names: dns
         })))));
      } else return bindError(vlparse(2, sp.snd), dnb => mapError(parseDistinguishedNames(dnb), dns => ({
         certificate_types: ctl,
         signature_algorithms: [],
         distinguished_names: dns
      })));
   });
}

const helloRequestBytes = messageBytes(HT.hello_request, util.empty_bytes);

const serverHelloDoneBytes = messageBytes(HT.server_hello_done, util.empty_bytes);

const defaultServerKeyExchange_ECDHE = function (dh_public) {
   return {
      kex: "ECDHE",
      ec_params: {
         curve: SG.secp256r1
      },
      ec_public: dh_public,
      sig: {
         sig_hash_alg: SS.rsa_pkcs1_sha256,
         sig_value: ""
      },
      sign: function (cr, sr, pv) {
         const kexB = "03" + this.ec_params.curve + vlbytes(1, this.ec_public);
         const sigv = cr + sr + kexB;
         if (pv == PV.TLS_1p0) {
            this.sig.sig_value = tls_crypto.rsa_sign(tls_crypto.server_key, tls_crypto.md5(sigv) + tls_crypto.sha1(sigv));
         } else {
            switch (this.sig.sig_hash_alg) {
               case SS.rsa_pkcs1_sha256:
                  this.sig.sig_value = tls_crypto.rsa_sha256(tls_crypto.server_key, sigv);break;
               case SS.rsa_pkcs1_sha1:
                  this.sig.sig_value = tls_crypto.rsa_sha1(tls_crypto.server_key, sigv);break;
               case SS.rsa_pkcs1_md5:
                  this.sig.sig_value = tls_crypto.rsa_md5(tls_crypto.server_key, sigv);break;
               default:
                  throw new Error("only RSA-SHA256/SHA1/MD5 signatures implemented");
            }
         }
      }
   };
};

const defaultServerKeyExchange_DHE = {
   kex: "DHE",
   dh_params: {
      dh_p: "00f488fd584e49dbcd20b49de49107366b336c380d451d0f7c88b31c" + "7c5b2d8ef6f3c923c043f0a55b188d8ebb558cb85d38d334fd7c175743" + "a31d186cde33212cb52aff3ce1b1294018118d7c84a70a72d686c40319" + "c807297aca950cd9969fabd00a509b0246d3083d66a45d419f9c7cbd89" + "4b221926baaba25ec355e92f78c7",
      dh_g: "02"
   },
   dh_public: "02",
   sig: {
      sig_hash_alg: SS.rsa_pkcs1_sha256,
      sig_value: util.zeroes(1024)
   },
   sign: function (cr, sr, pv) {
      const kexB = vlbytes(2, this.dh_params.dh_p) + vlbytes(2, this.dh_params.dh_g) + vlbytes(2, this.dh_public);
      const sigv = cr + sr + kexB;
      if (pv == PV.TLS_1p0) this.sig.sig_value = tls_crypto.rsa_sign(tls_crypto.server_key, tls_crypto.md5(sigv) + tls_crypto.sha1(sigv));else {
         switch (this.sig.sig_hash_alg) {
            case SS.rsa_pkcs1_sha256:
               this.sig.sig_value = tls_crypto.rsa_sha256(tls_crypto.server_key, sigv);break;
            case SS.rsa_pkcs1_sha1:
               this.sig.sig_value = tls_crypto.rsa_sha1(tls_crypto.server_key, sigv);break;
            case SS.rsa_pkcs1_md5:
               this.sig.sig_value = tls_crypto.rsa_md5(tls_crypto.server_key, sigv);break;
            default:
               throw new Error("only RSA-SHA256/SHA1/MD5 signatures implemented");
         }
      }
   }
};
const defaultServerKeyExchange_RSA = {
   kex: "RSA",
   rsa_public: {
      rsa_modulus: "00f488fd584e49dbcd20b49de49107366b336c380d451d0f7c88b31c" + "7c5b2d8ef6f3c923c043f0a55b188d8ebb558cb85d38d334fd7c175743a31d186" + "cde33212cb52aff3ce1b1294018118d7c84a70a72d686c40319c807297aca950c" + "d9969fabd00a509b0246d3083d66a45d419f9c7cbd894b221926baaba25ec355e" + "92f78c7",
      rsa_exponent: "010001"
   },
   sig: {
      sig_hash_alg: SS.rsa_pkcs1_sha256,
      sig_value: util.zeroes(1024)
   },
   sign: function (cr, sr, pv) {
      const kexB = vlbytes(2, this.rsa_public.rsa_modulus) + vlbytes(2, this.rsa_public.rsa_exponent);
      const sigv = cr + sr + kexB;
      if (pv == PV.TLS_1p0) this.sig.sig_value = tls_crypto.rsa_sign(tls_crypto.server_key, tls_crypto.md5(sigv) + tls_crypto.sha1(sigv));else {
         switch (this.sig.sig_hash_alg) {
            case SS.rsa_pkcs1_sha256:
               this.sig.sig_value = tls_crypto.rsa_sha256(tls_crypto.server_key, sigv);break;
            case SS.rsa_pkcs1_sha1:
               this.sig.sig_value = tls_crypto.rsa_sha1(tls_crypto.server_key, sigv);break;
            case SS.rsa_pkcs1_md5:
               this.sig.sig_value = tls_crypto.rsa_md5(tls_crypto.server_key, sigv);break;
            default:
               throw new Error("only RSA-SHA256/SHA1/MD5 signatures implemented");
         }
      }
   }
};

function serverKeyExchangeParamsBytes(ske) {
   let kexB = "";
   switch (ske.kex) {
      case "DHE":
         kexB = vlbytes(2, ske.dh_params.dh_p) + vlbytes(2, ske.dh_params.dh_g) + vlbytes(2, ske.dh_public);
         return kexB;
      case "ECDHE":
         kexB = "03" + ske.ec_params.curve + vlbytes(1, ske.ec_public);
         return kexB;
      case "RSA":
         kexB = vlbytes(2, ske.rsa_public.rsa_modulus) + vlbytes(2, ske.rsa_public.rsa_exponent);
         return kexB;
      default:
         throw "non DHE/ECDHE/RSA SKE not implemented" + new Error().stack;
   }
}

function serverKeyExchangeBytes(ske, pv) {
   let kexB = serverKeyExchangeParamsBytes(ske);
   let sig = "";
   if (pv == PV.TLS_1p2) sig = ske.sig.sig_hash_alg + vlbytes(2, ske.sig.sig_value);else sig = vlbytes(2, ske.sig.sig_value);
   return messageBytes(HT.server_key_exchange, kexB + sig);
}

function parseSignature(b, pv) {
   //    console.log("parseSignature version:"+pv+"="+PV.TLS_1p2);
   if (pv == PV.TLS_1p2 || pv == PV.TLS_1p3) {
      if (util.getLength(b) <= 2) return Incorrect(AD.decode_error, "TLS 1.2 signature not long enough");else {
         const sp1 = util.split(b, 2);
         console.log("parseSignature sighashalg:" + sp1.fst);
         return mapError(vlparse(2, sp1.snd), sv => {
            console.log("parseSignature sigval:" + sv);
            return {
               sig_hash_alg: sp1.fst,
               sig_value: sv
            };
         });
      }
   } else return mapError(vlparse(2, b), sv => {
      return {
         sig_hash_alg: "",
         sig_value: sv
      };
   });
}

function parseServerKeyExchange(b, pv, kex) {
   //    console.log("pv:"+pv+",kex:"+kex);
   switch (kex) {
      case "DHE":
         return bindError(vlsplit(2, b), sp1 => bindError(vlsplit(2, sp1.snd), sp2 => bindError(vlsplit(2, sp2.snd), sp3 => mapError(parseSignature(sp3.snd, pv), sig => ({
            kex: "DHE",
            dh_params: {
               dh_p: sp1.fst,
               dh_g: sp2.fst
            },
            dh_public: sp3.fst,
            sig: sig,
            sign: defaultServerKeyExchange_DHE.sign
         })))));
      case "ECDHE":
         if (util.getLength(b) < 4) return Incorrect(AD.decode_error, "ECDHE ske not long enough");else {
            const sp1 = util.split(b, 1);
            const sp2 = util.split(sp1.snd, 2);
            return bindError(vlsplit(1, sp2.snd), sp3 => mapError(parseSignature(sp3.snd, pv), sig => ({
               kex: "ECDHE",
               ec_params: {
                  curve: sp2.fst
               },
               ec_public: sp3.fst,
               sig: sig,
               sign: defaultServerKeyExchange_DHE.sign

            })));
         }
      case "RSA":
         return bindError(vlsplit(2, b), sp1 => bindError(vlsplit(2, sp1.snd), sp2 => mapError(parseSignature(sp2.snd, pv), sig => ({
            kex: "RSA",
            rsa_public: {
               rsa_modulus: sp1.fst,
               rsa_exponent: sp2.fst
            },
            sig: sig,
            sign: defaultServerKeyExchange_RSA.sign

         }))));
      default:
         throw "non DHE/ECDHE/RSA SKE not implemented" + stackTrace.get();
   }
};

const defaultClientKeyExchange_ECDHE = function (dh_public) {
   return {
      kex: "ECDHE",
      ec_public: dh_public
   };
};
const defaultClientKeyExchange_DHE = {
   kex: "DHE",
   dh_public: "02"
};
const defaultClientKeyExchange_RSA = {
   kex: "RSA",
   encpms: util.zeroes(1024)
};

function clientKeyExchangeBytes(cke, pv) {
   let kexB = "";
   switch (cke.kex) {
      case "DHE":
         kexB = vlbytes(2, cke.dh_public);
         break;
      case "ECDHE":
         kexB = vlbytes(1, cke.ec_public);
         break;
      case "RSA":
         kexB = pv == PV.SSL_3p0 ? cke.encpms : vlbytes(2, cke.encpms);
         break;
      default:
         throw "non RSA/DHE/ECDHE client key exchange not implemented";
   }
   return messageBytes(HT.client_key_exchange, kexB);
}

function parseClientKeyExchange(b, pv, kex) {
   //console.log("pcke - pv:"+pv+",kex:"+kex);
   switch (kex) {
      case "DHE":
         return mapError(vlparse(2, b), p => ({
            kex: "DHE",
            dh_public: p
         }));
      case "ECDHE":
         return mapError(vlparse(1, b), p => ({
            kex: "ECDHE",
            ec_public: p
         }));
      case "RSA":
         if (pv == PV.SSL_3p0) return Correct({
            kex: "RSA",
            encpms: b
         });else return mapError(vlparse(2, b), p => ({
            kex: "RSA",
            encpms: p
         }));
      default:
         throw "non RSA/DHE/ECDHE client key exchange not implemented";
   }
}
const defaultClientCertificate = {
   chain: [tls_crypto.client_cert.hex]
};

const defaultCertificateVerify = {
   sig: {
      sig_hash_alg: SS.rsa_pkcs1_sha256,
      sig_value: util.zeroes(1024)
   },
   signClient: function (log) {
      this.sig.sig_value = tls_crypto.rsa_sha256(tls_crypto.client_key, log);
   },
   signServer: function (log) {
      this.sig.sig_value = tls_crypto.rsa_sha256(tls_crypto.server_key, log);
   }
};

function certificateVerifyBytes(cv, pv) {
   let sig = "";
   if (pv === PV.TLS_1p2 || pv === PV.TLS_1p3) sig = cv.sig.sig_hash_alg + vlbytes(2, cv.sig.sig_value);else sig = vlbytes(2, cv.sig.sig_value);
   return messageBytes(HT.certificate_verify, sig);
}

function parseCertificateVerify(b, pv) {
   return mapError(parseSignature(b, pv), sig => {
      return {
         sig: sig
      };
   });
}

const defaultFinished = {
   verify_data: util.zeroes(24)
};

function finishedBytes(fin) {
   return messageBytes(HT.finished, fin.verify_data);
}

function parseFinished(b) {
   return Correct({
      verify_data: b
   });
}

const defaultEncryptedExtensions = {
   extensions: ""
};

function encryptedExtensionsBytes() {
   return messageBytes(HT.encrypted_extensions, vlbytes(2, util.empty_bytes));
}

function sessionTicketBytes(tick, pv) {
   if (pv === PV.TLS_1p3) return messageBytes(HT.session_ticket, "00000000" + "00000000" + vlbytes(2, tick.ticket) + vlbytes(2, ""));else return messageBytes(HT.session_ticket, "00000000" + vlbytes(2, tick.ticket));
}

function parseEncryptedExtensions(b) {
   return mapError(vlparse(2, b), eel => {
      return {
         extensions: b
      };
   });
}

function parseSessionTicket(b, pv) {
   if (util.getLength(b) < 6) return Incorrect(AD.decode_error, "no lifetime");
   const sp = util.split(b, 4);
   const lt = util.int_of_bytes(sp.fst, 4);
   if (pv === PV.TLS_1p3) {
      if (util.getLength(sp.snd) < 6) return Incorrect(AD.decode_error, "no flags");
      const sp2 = util.split(sp.snd, 4);
      let flags = sp2.fst;
      return bindError(vlsplit(2, sp2.snd), sp => mapError(vlparse(2, sp.snd), t => {
         return {
            lifetime: lt,
            flags: flags,
            extensions: sp2.fst,
            ticket: t
         };
      }));
   } else return mapError(vlparse(2, sp.snd), t => {
      return {
         lifetime: lt,
         ticket: t
      };
   });
}

function parseHandshakeMessage(m, pv, kex, from_server) {
   //console.log("phm - pv:"+pv+",kex:"+kex);
   //     console.log(m);
   if (typeof m.pl !== "string") throw "Already parsed, payload not a string\n" + new Error().stack;

   switch (m.ht) {
      case HT.client_hello:
         return parseClientHello(m.pl);
      case HT.server_hello:
         return parseServerHello(m.pl);
      case HT.certificate:
         return parseCertificate(m.pl, pv, from_server);
      case HT.server_key_exchange:
         return parseServerKeyExchange(m.pl, pv, kex);
      case HT.server_hello_done:
         if (util.getLength(m.pl) == 0) return Correct(util.empty_bytes);else return Incorrect(AD.decode_error, "serverHello done is not empty");
      case HT.certificate_request:
         return parseCertificateRequest(m.pl, pv);
      case HT.client_key_exchange:
         return parseClientKeyExchange(m.pl, pv, kex);
      case HT.certificate_verify:
         return parseCertificateVerify(m.pl, pv);
      case HT.finished:
         return parseFinished(m.pl);
      case HT.encrypted_extensions:
         return parseEncryptedExtensions(m.pl);
      case HT.session_ticket:
         return parseSessionTicket(m.pl, pv);
      default:
         throw "Parsing for HT=" + m.ht + " not implemented\n" + new Error().stack;
   }
}

/*
  function parseLog(l:string, pv:string, kex:string) : pair<result<[hs_msg]>,[ {
  let msgs = [];
  while (util.getLength(l) > 0) {
  //console.log(l.length);
  const msg = parseMessage(l).bind(sp => (sp.fst == undefined ? Correct(undefined) :
  parseHandshakeMessage(sp.fst, pv, kex).map(m => Pair(Pair(sp.fst.ht, m),
  sp.snd))));
  if (msg == undefined) return Pair(Incorrect(AD.decode_error,
  "log must not contain incomplete messages"), msgs);
  switch (msg.result) {
  case "Error":
  return Pair(msg, msgs);
  case "Correct":
  msgs.push({
  ht: msg.value.fst.fst,
  pl: msg.value.fst.snd
  });
  l = msg.value.snd;
  break;
  default:
  throw ("getResult returned non-Result" + (new Error()).stack)
  }

  //console.log(l.length);
  }
  return Pair(Correct(msgs), []);
  };
*/
/*  Record layer  */
const ContentType = {
   change_cipher_spec: "14",
   alert: "15",
   handshake: "16",
   application_data: "17"
};
const ContentType_rev = reverse(ContentType);

function ContentType_lookup(x) {
   return lookup(ContentType_rev, x);
};

function serializeRecord(r) {
   if (debug) console.log(r);
   return r.type + r.version + vlbytes(2, r.fragment);
}

function parseRecord(b) {
   if (util.getLength(b) < 5) return Incorrect(AD.decode_error, "parseRecord: record has less than 5 bytes");
   const sp1 = util.split(b, 1);
   const sp2 = util.split(b, 2);
   return mapError(vlparse(2, sp2.snd), f => ({
      type: sp1.fst,
      version: sp2.fst,
      fragment: f
   }));
}

function splitRecord(b) {
   if (util.getLength(b) < 5) return Incorrect(AD.decode_error, "splitRecord: record has less than 5 bytes");
   const sp1 = util.split(b, 1);
   const sp2 = util.split(sp1.snd, 2);
   return mapError(vlsplit(2, sp2.snd), f => Pair({
      type: sp1.fst,
      version: sp2.fst,
      fragment: f.fst
   }, f.snd));
}

module.exports = {
   stackTrace: stackTrace,
   Correct: Correct,
   Incorrect: Incorrect,
   Pair: Pair,
   reverse: reverse,
   AD: AD,
   AD_lookup: AD_lookup,
   PV: PV,
   PV_lookup: PV_lookup,
   CM: CM,
   CM_lookup: CM_lookup,
   CS: CS,
   CS_lookup: CS_lookup,
   HT: HT,
   HT_lookup: HT_lookup,
   EXT: EXT,
   EXT_lookup: EXT_lookup,
   HA: HA,
   HA_lookup: HA_lookup,
   SA: SA,
   SA_lookup: SA_lookup,
   SG: SG,
   SG_lookup: SG_lookup,
   PF: PF,
   PF_lookup: PF_lookup,
   CT: CT,
   CT_lookup: CT_lookup,
   SS: SS,
   SS_lookup: SS_lookup,
   ContentType: ContentType,
   ContentType_lookup: ContentType_lookup,
   KEX: KEX,
   AE: AE,
   vlbytes: vlbytes,
   vlsplit: vlsplit,
   vlparse: vlparse,
   messageBytes: messageBytes,
   parseMessage: parseMessage,
   clientHelloBytes: clientHelloBytes,
   parseClientHello: parseClientHello,
   defaultClientHello: defaultClientHello,
   serverHelloBytes: serverHelloBytes,
   parseServerHello: parseServerHello,
   defaultServerHello: defaultServerHello,
   certificateBytes: certificateBytes,
   parseCertificate: parseCertificate,
   defaultServerCertificate: defaultServerCertificate,
   defaultClientCertificate: defaultClientCertificate,
   certificateRequestBytes: certificateRequestBytes,
   parseCertificateRequest: parseCertificateRequest,
   defaultCertificateRequest: defaultCertificateRequest,
   helloRequestBytes: helloRequestBytes,
   serverHelloDoneBytes: serverHelloDoneBytes,
   serverKeyExchangeBytes: serverKeyExchangeBytes,
   serverKeyExchangeParamsBytes: serverKeyExchangeParamsBytes,
   parseServerKeyExchange: parseServerKeyExchange,
   defaultServerKeyExchange_ECDHE: defaultServerKeyExchange_ECDHE,
   defaultServerKeyExchange_DHE: defaultServerKeyExchange_DHE,
   defaultServerKeyExchange_RSA: defaultServerKeyExchange_RSA,
   clientKeyExchangeBytes: clientKeyExchangeBytes,
   parseClientKeyExchange: parseClientKeyExchange,
   defaultClientKeyExchange_ECDHE: defaultClientKeyExchange_ECDHE,
   defaultClientKeyExchange_DHE: defaultClientKeyExchange_DHE,
   defaultClientKeyExchange_RSA: defaultClientKeyExchange_RSA,
   defaultCertificateVerify: defaultCertificateVerify,
   certificateVerifyBytes: certificateVerifyBytes,
   parseCertificateVerify: parseCertificateVerify,
   defaultEncryptedExtensions: defaultEncryptedExtensions,
   encryptedExtensionsBytes: encryptedExtensionsBytes,
   sessionTicketBytes: sessionTicketBytes,
   finishedBytes: finishedBytes,
   parseFinished: parseFinished,
   defaultFinished: defaultFinished,
   parseHandshakeMessage: parseHandshakeMessage,
   //		parseLog: parseLog,
   serializeRecord: serializeRecord,
   parseRecord: parseRecord,
   splitRecord: splitRecord,
   mapError: mapError,
   bindError: bindError
};