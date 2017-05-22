/*  weak */
"use strict";

var debug = false;
var stackTrace = require('stack-trace');
var fs = require('fs');
var net = require('net');
var util = require('./util.js');
var tls_crypto = require('./tls_crypto.js');
var rsasign = require('jsrsasign');
var formats = require('./tls_formats.js');
var handshake = require('./tls_handshake.js');
//	var typechecked = require('./tls_typechecked.js');
var Correct = formats.Correct;
var Incorrect = formats.Incorrect;
/* Begin: tls-prettyprint.js - printing TLS messages */

function printCipherSuites(cs) {
			const ncs = [];
			for (var i = 0; i < cs.length; i++) ncs[i] = formats.CS_lookup(cs[i]);
			return ncs;
}

function printCompressions(cm) {
			const ncm = [];
			for (var i = 0; i < cm.length; i++) ncm[i] = formats.CM_lookup(cm[i]);
			return ncm;
}

function printClientExtension(i, e) {
			switch (i) {
						case formats.EXT.server_name:
									return e.map(x => util.hex2a(x.host_name));
						case formats.EXT.signature_algorithms:
									return e.map(x => formats.SS_lookup(x));
						case formats.EXT.supported_versions:
									return e.map(x => formats.PV_lookup(x));
						case formats.EXT.supported_groups:
									return e.map(x => formats.SG_lookup(x));
						case formats.EXT.ec_point_format:
									return e.map(x => formats.PF_lookup(x));
						case formats.EXT.application_layer_protocol_negotiation:
									return e.map(x => util.hex2a(x));
						case formats.EXT.next_protocol_negotiation:
									return e.map(x => util.hex2a(x));
						case formats.EXT.key_share:
									return e.map(x => ({ dh_group: formats.SG_lookup(x.dh_group),
												dh_public: x.dh_public }));
						default:
									return e;
			}
}

function printClientExtensions(ext) {
			const next = {};
			for (var i in ext) next[formats.EXT_lookup(i)] = printClientExtension(i, ext[i]);
			return next;
}

function printClientHello(ch) {
			return {
						protocol_version: formats.PV_lookup(ch.protocol_version),
						client_random: ch.client_random,
						sessionID: ch.sessionID,
						cipher_suites: printCipherSuites(ch.cipher_suites),
						compression: printCompressions(ch.compressions),
						extensions: printClientExtensions(ch.extensions)
			};
}

function printServerExtension(i, e) {
			switch (i) {
						case formats.EXT.ec_point_format:
									return formats.PF_lookup(e);
						case formats.EXT.application_layer_protocol_negotiation:
									return e.map(x => util.hex2a(x));
						case formats.EXT.next_protocol_negotiation:
									return e.map(x => util.hex2a(x));
						case formats.EXT.key_share:
									return { dh_group: formats.SG_lookup(e.dh_group),
												dh_public: e.dh_public };
						default:
									return e;
			}
}

function printServerExtensions(ext) {
			const next = {};
			for (var i in ext) next[formats.EXT_lookup(i)] = printServerExtension(i, ext[i]);
			return next;
}

function printServerHello(sh) {
			return {
						protocol_version: formats.PV_lookup(sh.protocol_version),
						server_random: sh.server_random,
						sessionID: sh.sessionID,
						cipher_suite: formats.CS_lookup(sh.cipher_suite),
						compression: formats.CM_lookup(sh.compression),
						extensions: printServerExtensions(sh.extensions)
			};
}

function printCertificate(c) {
			return c.chain.map(c => {
						return "Subject:" + tls_crypto.cert_get_subject(c);
			});
}

function printCertificateRequest(scr) {
			return {
						certificate_types: scr.certificate_types.map(ct => formats.CT_lookup(ct)),
						signature_algorithms: scr.signature_algorithms.map(e => formats.SS_lookup(e)),
						distinguished_names: scr.distinguished_names.map(e => rsasign.X509.hex2dn(e))
			};
}

function printServerKeyExchange(ske) {
			switch (ske.kex) {
						case "DHE":
									return {
												kex: ske.kex,
												dh_params: ske.dh_params,
												dh_public: ske.dh_public,
												sig: {
															hash_alg: formats.HA_lookup(ske.sig.hash_alg),
															sig_alg: formats.SA_lookup(ske.sig.sig_alg),
															sig_value: ske.sig.sig_value
												}
									};
						case "ECDHE":
									return {
												kex: ske.kex,
												ec_params: {
															curve: formats.SG_lookup(ske.ec_params.curve)
												},
												ec_public: ske.ec_public,
												sig: {
															hash_alg: formats.HA_lookup(ske.sig.hash_alg),
															sig_alg: formats.SA_lookup(ske.sig.sig_alg),
															sig_value: ske.sig.sig_value
												}
									};
						case "RSA":
									return {
												kex: ske.kex,
												rsa_public: ske.rsa_public,
												sig: {
															hash_alg: formats.HA_lookup(ske.sig.hash_alg),
															sig_alg: formats.SA_lookup(ske.sig.sig_alg),
															sig_value: ske.sig.sig_value
												}
									};
						default:
									throw "SKE not defined for non DHE/ECDHE" + new Error().stack;
			}
}

function printCertificateVerify(cr) {
			return {
						sig: {
									hash_alg: formats.HA_lookup(cr.sig.hash_alg),
									sig_alg: formats.SA_lookup(cr.sig.sig_alg),
									sig_value: cr.sig.sig_value
						}
			};
}

function printHandshakeMessage(msg) {
			switch (msg.ht) {
						case formats.HT.client_hello:
									return {
												ht: "client_hello",
												pl: printClientHello(msg.pl)
									};
						case formats.HT.server_hello:
									return {
												ht: "server_hello",
												pl: printServerHello(msg.pl)
									};
						case formats.HT.certificate:
									return {
												ht: "certificate",
												pl: printCertificate(msg.pl)
									};
						case formats.HT.server_key_exchange:
									return {
												ht: "server_key_exchange",
												pl: printServerKeyExchange(msg.pl)
									};
						case formats.HT.certificate_request:
									return {
												ht: "certificate_request",
												pl: printCertificateRequest(msg.pl)
									};
						case formats.HT.server_hello_done:
									return {
												ht: "server_hello_done",
												pl: msg.pl
									};
						case formats.HT.client_key_exchange:
									return {
												ht: "client_key_exchange",
												pl: msg.pl
									};
						case formats.HT.certificate_verify:
									return {
												ht: "certificate_verify",
												pl: printCertificateVerify(msg.pl)
									};
						case formats.HT.finished:
									return {
												ht: "finished",
												pl: msg.pl
									};
						default:
									return {
												ht: formats.HT_lookup(msg.ht),
												pl: msg.pl
									};
			}
}

function printLog(l) {
			return JSON.stringify(l.map(printHandshakeMessage), null, "\t");
}

function printResult(r) {
			switch (r.result) {
						case "Correct":
									return "Correct:\n" + JSON.stringify(r.value, null, "\t");
						case "Error":
									return "ERROR: " + formats.AD_lookup(r.code) + "\n" + r.desc;
						default:
									throw "printResult given non-result";
			}
}
/* Begin: tls-tests.js - unit tests */
/* TESTING message formats */

function testFormats() {
			var chb = formats.clientHelloBytes({
						protocol_version: formats.PV.TLS_1p2,
						client_random: util.zeroes(64),
						sessionID: "",
						cipher_suites: [],
						compressions: [],
						extensions: []
			});
			console.log(chb);
			console.log(JSON.stringify(formats.parseClientHello("0303000000000000000000000000000000000000000000000000000000000000000000000000").map(printClientHello)));
			console.log(JSON.stringify(formats.parseMessage(chb).bind(msg => formats.parseClientHello(msg.fst.pl).map(printClientHello))));
			var chtrace1 = "01 00 01 35 03 03 aa 87 3b b4 bd d1 d7 37 9f f6 62 77 ec 17 8f 36 de 40 b6 76 f1 eb 03 18 0d 71 fc f4 8f 8c a5 5d 00 00 b6 c0 30 c0 2c c0 28 c0 24 c0 14 c0 0a 00 a5 00 a3 00 a1 00 9f 00 6b 00    6a 00 69 00 68 00 39 00 38 00 37 00 36 00 88 00    87 00 86 00 85 c0 32 c0 2e c0 2a c0 26 c0 0f c0    05 00 9d 00 3d 00 35 00 84 c0 2f c0 2b c0 27 c0    23 c0 13 c0 09 00 a4 00 a2 00 a0 00 9e 00 67 00    40 00 3f 00 3e 00 33 00 32 00 31 00 30 00 9a 00    99 00 98 00 97 00 45 00 44 00 43 00 42 c0 31 c0    2d c0 29 c0 25 c0 0e c0 04 00 9c 00 3c 00 2f 00    96 00 41 00 07 c0 11 c0 07 c0 0c c0 02 00 05 00    04 c0 12 c0 08 00 16 00 13 00 10 00 0d c0 0d c0    03 00 0a 00 15 00 12 00 0f 00 0c 00 09 00 ff 02    01 00 00 55 00 0b 00 04 03 00 01 02 00 0a 00 1c    00 1a 00 17 00 19 00 1c 00 1b 00 18 00 1a 00 16    00 0e 00 0d 00 0b 00 0c 00 09 00 0a 00 23 00 00    00 0d 00 20 00 1e 06 01 06 02 06 03 05 01 05 02    05 03 04 01 04 02 04 03 03 01 03 02 03 03 02 01    02 02 02 03 00 0f 00 01 01";
			var chtrace2 = "01 00 00 c5 03 03 0b 19 6a bc 47 aa c0 89 ec cc  a0 a3 46 a8 45 6e 29 99 f1 af 72 e7 f3 c0 c3 824f 30 bc 7e 8f 6b 00 00 22 c0 2b c0 2f 00 9e cc    14 cc 13 cc 15 c0 0a c0 14 00 39 c0 09 c0 13 00  33 00 9c 00 35 00 2f 00 0a 00 ff 01 00 00 7a 00  00 00 0e 00 0c 00 00 09 6c 6f 63 61 6c 68 6f 73  74 00 17 00 00 00 23 00 00 00 0d 00 16 00 14 06  01 06 03 05 01 05 03 04 01 04 03 03 01 03 03 02  01 02 03 00 05 00 05 01 00 00 00 00 33 74 00 00  00 12 00 00 00 10 00 1d 00 1b 08 68 74 74 70 2f  31 2e 31 08 73 70 64 79 2f 33 2e 31 05 68 32 2d  31 34 02 68 32 75 50 00 00 00 0b 00 02 01 00 00  0a 00 06 00 04 00 17 00 18";
			chtrace1 = chtrace1.replace(/\s/g, "");
			chtrace2 = chtrace2.replace(/\s/g, "");

			function testMessage(trace, parse, gen, print) {
						var msg = formats.parseMessage(trace).bind(msg => parse(msg.fst.pl));
						console.log(JSON.stringify(msg.map(print), null, '\t'));
						switch (msg.result) {
									case "Correct":
												var ntrace = gen(msg.value);
												var nmsg = formats.parseMessage(ntrace).bind(msg => parse(msg.fst.pl));
												console.log(JSON.stringify(nmsg.map(print), null, '\t'));
									default:
												break;
						}
			}
			testMessage(chtrace1, formats.parseClientHello, formats.clientHelloBytes, printClientHello);
			testMessage(chtrace2, formats.parseClientHello, formats.clientHelloBytes, printClientHello);
			var ch1 = formats.parseMessage(chtrace1).bind(msg => formats.parseClientHello(msg.fst.pl));
			var shtrace1 = "02 00 00 65 03 03 55 9d 8f 95 3e 4d 39 09 34 09    d4 7c a8 82 56 a0 11 90 16 4b f5 06 f8 8b b9 fb    66 ad 3b 35 8b fe 00 c0 2f 00 00 3d ff 01 00 01    00 00 0b 00 04 03 00 01 02 00 23 00 00 33 74 00    28 02 68 32 05 68 32 2d 31 35 05 68 32 2d 31 34    08 73 70 64 79 2f 33 2e 31 06 73 70 64 79 2f 33    08 68 74 74 70 2f 31 2e 31".replace(/\s/g, "");
			var shtrace2 = "02 00 00 36 03 03 47 fd 98 74 97 90 20 c2 1b b6    72 38 43 a3 57 82 84 44 95 a2 9f 56 0f f8 7f 7c    2e 1b f1 a3 c2 63 00 00 9f 00 00 0e ff 01 00 01    00 00 23 00 00 00 0f 00 01 01".replace(/\s/g, "");
			testMessage(shtrace1, formats.parseServerHello, formats.serverHelloBytes, printServerHello);
			testMessage(shtrace2, formats.parseServerHello, formats.serverHelloBytes, printServerHello);
			var sctrace1 = "0b 00 0f 08 00 0f 05 00 07 87 30 82 07 83 30 82    06 6b a0 03 02 01 02 02 08 5f d2 50 a2 e6 f6 71    3a 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00    30 49 31 0b 30 09 06 03 55 04 06 13 02 55 53 31    13 30 11 06 03 55 04 0a 13 0a 47 6f 6f 67 6c 65    20 49 6e 63 31 25 30 23 06 03 55 04 03 13 1c 47    6f 6f 67 6c 65 20 49 6e 74 65 72 6e 65 74 20 41    75 74 68 6f 72 69 74 79 20 47 32 30 1e 17 0d 31    35 30 36 31 38 31 30 31 35 31 39 5a 17 0d 31 35    30 39 31 36 30 30 30 30 30 30 5a 30 66 31 0b 30    09 06 03 55 04 06 13 02 55 53 31 13 30 11 06 03    55 04 08 0c 0a 43 61 6c 69 66 6f 72 6e 69 61 31    16 30 14 06 03 55 04 07 0c 0d 4d 6f 75 6e 74 61    69 6e 20 56 69 65 77 31 13 30 11 06 03 55 04 0a    0c 0a 47 6f 6f 67 6c 65 20 49 6e 63 31 15 30 13    06 03 55 04 03 0c 0c 2a 2e 67 6f 6f 67 6c 65 2e    63 6f 6d 30 82 01 22 30 0d 06 09 2a 86 48 86 f7    0d 01 01 01 05 00 03 82 01 0f 00 30 82 01 0a 02    82 01 01 00 99 ed 14 df 26 7f 8e 52 6b 36 d8 f1    23 1b 47 41 4e 96 60 4f aa fe 52 0b b2 1c a2 89    b8 0b 07 29 54 86 83 47 91 e2 45 52 87 2b 14 d1    f1 8b 5f 00 38 49 a6 f9 3d a7 ce 01 aa c5 fa e2    03 fe ec b2 ce fe 4f 17 ad 1f a0 33 89 7f 13 40    6f 0b 10 7d 79 53 aa 1b 82 10 22 11 fa a8 ef 9e    d0 85 96 63 45 70 99 8d 9b a1 6c 0f b5 c7 d0 5e    ad de 4b 42 6f b3 6d 76 b6 e6 58 40 5d b3 30 0d    da 24 82 e5 0d ec 8d e1 0f 51 34 76 55 91 86 21    13 b0 b0 e2 8f 77 17 da 10 43 2a 0d 55 1e a8 4a    e0 61 62 b9 97 28 67 e3 69 e7 ea a2 bc be 73 5d    1c 8e 5f cb 90 bf 55 9c 61 46 19 85 9c 2f 32 ae    1d 3c 4c 13 4d 13 bd 5d 51 1a 44 00 b2 c9 a6 81    8d 7d 75 92 97 03 61 f2 8a 67 f3 7a 6b 9b db 51    ee 08 ee 9d 73 99 31 eb 24 d4 e9 39 d9 0e fe 97    d0 f6 66 c9 99 40 81 77 3c 60 00 a8 6b ca 98 c8    c2 5e bb 93 02 03 01 00 01 a3 82 04 50 30 82 04    4c 30 1d 06 03 55 1d 25 04 16 30 14 06 08 2b 06    01 05 05 07 03 01 06 08 2b 06 01 05 05 07 03 02    30 82 03 26 06 03 55 1d 11 04 82 03 1d 30 82 03    19 82 0c 2a 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 82    0d 2a 2e 61 6e 64 72 6f 69 64 2e 63 6f 6d 82 16    2a 2e 61 70 70 65 6e 67 69 6e 65 2e 67 6f 6f 67    6c 65 2e 63 6f 6d 82 12 2a 2e 63 6c 6f 75 64 2e    67 6f 6f 67 6c 65 2e 63 6f 6d 82 16 2a 2e 67 6f    6f 67 6c 65 2d 61 6e 61 6c 79 74 69 63 73 2e 63    6f 6d 82 0b 2a 2e 67 6f 6f 67 6c 65 2e 63 61 82    0b 2a 2e 67 6f 6f 67 6c 65 2e 63 6c 82 0e 2a 2e    67 6f 6f 67 6c 65 2e 63 6f 2e 69 6e 82 0e 2a 2e    67 6f 6f 67 6c 65 2e 63 6f 2e 6a 70 82 0e 2a 2e    67 6f 6f 67 6c 65 2e 63 6f 2e 75 6b 82 0f 2a 2e    67 6f 6f 67 6c 65 2e 63 6f 6d 2e 61 72 82 0f 2a    2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2e 61 75 82 0f    2a 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2e 62 72 82    0f 2a 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2e 63 6f    82 0f 2a 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2e 6d    78 82 0f 2a 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2e    74 72 82 0f 2a 2e 67 6f 6f 67 6c 65 2e 63 6f 6d    2e 76 6e 82 0b 2a 2e 67 6f 6f 67 6c 65 2e 64 65    82 0b 2a 2e 67 6f 6f 67 6c 65 2e 65 73 82 0b 2a    2e 67 6f 6f 67 6c 65 2e 66 72 82 0b 2a 2e 67 6f    6f 67 6c 65 2e 68 75 82 0b 2a 2e 67 6f 6f 67 6c    65 2e 69 74 82 0b 2a 2e 67 6f 6f 67 6c 65 2e 6e    6c 82 0b 2a 2e 67 6f 6f 67 6c 65 2e 70 6c 82 0b    2a 2e 67 6f 6f 67 6c 65 2e 70 74 82 12 2a 2e 67    6f 6f 67 6c 65 61 64 61 70 69 73 2e 63 6f 6d 82    0f 2a 2e 67 6f 6f 67 6c 65 61 70 69 73 2e 63 6e    82 14 2a 2e 67 6f 6f 67 6c 65 63 6f 6d 6d 65 72    63 65 2e 63 6f 6d 82 11 2a 2e 67 6f 6f 67 6c 65    76 69 64 65 6f 2e 63 6f 6d 82 0c 2a 2e 67 73 74    61 74 69 63 2e 63 6e 82 0d 2a 2e 67 73 74 61 74    69 63 2e 63 6f 6d 82 0a 2a 2e 67 76 74 31 2e 63    6f 6d 82 0a 2a 2e 67 76 74 32 2e 63 6f 6d 82 14    2a 2e 6d 65 74 72 69 63 2e 67 73 74 61 74 69 63    2e 63 6f 6d 82 0c 2a 2e 75 72 63 68 69 6e 2e 63    6f 6d 82 10 2a 2e 75 72 6c 2e 67 6f 6f 67 6c 65    2e 63 6f 6d 82 16 2a 2e 79 6f 75 74 75 62 65 2d    6e 6f 63 6f 6f 6b 69 65 2e 63 6f 6d 82 0d 2a 2e    79 6f 75 74 75 62 65 2e 63 6f 6d 82 16 2a 2e 79    6f 75 74 75 62 65 65 64 75 63 61 74 69 6f 6e 2e    63 6f 6d 82 0b 2a 2e 79 74 69 6d 67 2e 63 6f 6d    82 0b 61 6e 64 72 6f 69 64 2e 63 6f 6d 82 04 67    2e 63 6f 82 06 67 6f 6f 2e 67 6c 82 14 67 6f 6f    67 6c 65 2d 61 6e 61 6c 79 74 69 63 73 2e 63 6f    6d 82 0a 67 6f 6f 67 6c 65 2e 63 6f 6d 82 12 67    6f 6f 67 6c 65 63 6f 6d 6d 65 72 63 65 2e 63 6f    6d 82 0a 75 72 63 68 69 6e 2e 63 6f 6d 82 08 79    6f 75 74 75 2e 62 65 82 0b 79 6f 75 74 75 62 65    2e 63 6f 6d 82 14 79 6f 75 74 75 62 65 65 64 75    63 61 74 69 6f 6e 2e 63 6f 6d 30 68 06 08 2b 06    01 05 05 07 01 01 04 5c 30 5a 30 2b 06 08 2b 06    01 05 05 07 30 02 86 1f 68 74 74 70 3a 2f 2f 70    6b 69 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 47 49    41 47 32 2e 63 72 74 30 2b 06 08 2b 06 01 05 05    07 30 01 86 1f 68 74 74 70 3a 2f 2f 63 6c 69 65    6e 74 73 31 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f    6f 63 73 70 30 1d 06 03 55 1d 0e 04 16 04 14 07    c4 f2 e2 e0 ad 28 bb 03 82 ec d8 f0 6d df 93 37    95 02 f1 30 0c 06 03 55 1d 13 01 01 ff 04 02 30    00 30 1f 06 03 55 1d 23 04 18 30 16 80 14 4a dd    06 16 1b bc f6 68 b5 76 f5 81 b6 bb 62 1a ba 5a    81 2f 30 17 06 03 55 1d 20 04 10 30 0e 30 0c 06    0a 2b 06 01 04 01 d6 79 02 05 01 30 30 06 03 55    1d 1f 04 29 30 27 30 25 a0 23 a0 21 86 1f 68 74    74 70 3a 2f 2f 70 6b 69 2e 67 6f 6f 67 6c 65 2e    63 6f 6d 2f 47 49 41 47 32 2e 63 72 6c 30 0d 06    09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 82 01 01    00 72 22 f9 d9 7f 44 63 1b bb 69 c9 1d 54 3d 16    06 d6 09 bb 8d 78 52 c7 28 cc 6a 40 f0 c5 a2 0c    4d 33 f7 e8 7a 7f 6f 0c 60 e8 f6 3d 62 1a da 5e    0d 8c 63 6e 2f 86 15 1c 7c 5d aa 28 56 c5 a8 bf    9b 2f fb 5e b2 e7 7c 55 3e 57 d5 1d ed 62 1e 51    88 b4 05 fd bf da 14 f1 ca 41 c5 15 ed 35 83 fe    06 1e 30 6a 18 11 ac 92 e4 96 4d bf 8c d8 f0 e1    9d 47 2e 93 31 10 af d2 9f 48 2a 88 cc 1f 80 4e    e5 37 04 5f 19 18 9e dd 4d 85 a6 49 18 80 99 40    dd af 8a a7 26 5d 90 3a 39 5c 2b 79 90 41 62 1f    1b e8 99 05 5f c4 46 90 81 51 9f 4a 30 0d 12 a8    c1 da e3 cf 39 6e 98 2b 9b 78 3c e1 73 bb 67 53    90 ee 49 f6 d7 0e e9 90 5d 9c f9 af a8 86 0c d8    dc 7f 82 04 15 67 ff d7 a3 a1 24 ca da c7 99 97    bd fd b8 1e 81 50 5f ac e7 c2 3b 5c 72 4a 3b 6e    10 84 fd 5d 81 90 91 09 cb 54 dd 59 c0 7b cc 54    a9 00 03 f4 30 82 03 f0 30 82 02 d8 a0 03 02 01    02 02 03 02 3a 76 30 0d 06 09 2a 86 48 86 f7 0d    01 01 05 05 00 30 42 31 0b 30 09 06 03 55 04 06    13 02 55 53 31 16 30 14 06 03 55 04 0a 13 0d 47    65 6f 54 72 75 73 74 20 49 6e 63 2e 31 1b 30 19    06 03 55 04 03 13 12 47 65 6f 54 72 75 73 74 20    47 6c 6f 62 61 6c 20 43 41 30 1e 17 0d 31 33 30    34 30 35 31 35 31 35 35 35 5a 17 0d 31 36 31 32    33 31 32 33 35 39 35 39 5a 30 49 31 0b 30 09 06    03 55 04 06 13 02 55 53 31 13 30 11 06 03 55 04    0a 13 0a 47 6f 6f 67 6c 65 20 49 6e 63 31 25 30    23 06 03 55 04 03 13 1c 47 6f 6f 67 6c 65 20 49    6e 74 65 72 6e 65 74 20 41 75 74 68 6f 72 69 74    79 20 47 32 30 82 01 22 30 0d 06 09 2a 86 48 86    f7 0d 01 01 01 05 00 03 82 01 0f 00 30 82 01 0a    02 82 01 01 00 9c 2a 04 77 5c d8 50 91 3a 06 a3    82 e0 d8 50 48 bc 89 3f f1 19 70 1a 88 46 7e e0    8f c5 f1 89 ce 21 ee 5a fe 61 0d b7 32 44 89 a0    74 0b 53 4f 55 a4 ce 82 62 95 ee eb 59 5f c6 e1    05 80 12 c4 5e 94 3f bc 5b 48 38 f4 53 f7 24 e6    fb 91 e9 15 c4 cf f4 53 0d f4 4a fc 9f 54 de 7d    be a0 6b 6f 87 c0 d0 50 1f 28 30 03 40 da 08 73    51 6c 7f ff 3a 3c a7 37 06 8e bd 4b 11 04 eb 7d    24 de e6 f9 fc 31 71 fb 94 d5 60 f3 2e 4a af 42    d2 cb ea c4 6a 1a b2 cc 53 dd 15 4b 8b 1f c8 19    61 1f cd 9d a8 3e 63 2b 84 35 69 65 84 c8 19 c5    46 22 f8 53 95 be e3 80 4a 10 c6 2a ec ba 97 20    11 c7 39 99 10 04 a0 f0 61 7a 95 25 8c 4e 52 75    e2 b6 ed 08 ca 14 fc ce 22 6a b3 4e cf 46 03 97    97 03 7e c0 b1 de 7b af 45 33 cf ba 3e 71 b7 de    f4 25 25 c2 0d 35 89 9d 9d fb 0e 11 79 89 1e 37    c5 af 8e 72 69 02 03 01 00 01 a3 81 e7 30 81 e4    30 1f 06 03 55 1d 23 04 18 30 16 80 14 c0 7a 98    68 8d 89 fb ab 05 64 0c 11 7d aa 7d 65 b8 ca cc    4e 30 1d 06 03 55 1d 0e 04 16 04 14 4a dd 06 16    1b bc f6 68 b5 76 f5 81 b6 bb 62 1a ba 5a 81 2f    30 12 06 03 55 1d 13 01 01 ff 04 08 30 06 01 01    ff 02 01 00 30 0e 06 03 55 1d 0f 01 01 ff 04 04    03 02 01 06 30 35 06 03 55 1d 1f 04 2e 30 2c 30    2a a0 28 a0 26 86 24 68 74 74 70 3a 2f 2f 67 2e    73 79 6d 63 62 2e 63 6f 6d 2f 63 72 6c 73 2f 67    74 67 6c 6f 62 61 6c 2e 63 72 6c 30 2e 06 08 2b    06 01 05 05 07 01 01 04 22 30 20 30 1e 06 08 2b    06 01 05 05 07 30 01 86 12 68 74 74 70 3a 2f 2f    67 2e 73 79 6d 63 64 2e 63 6f 6d 30 17 06 03 55    1d 20 04 10 30 0e 30 0c 06 0a 2b 06 01 04 01 d6    79 02 05 01 30 0d 06 09 2a 86 48 86 f7 0d 01 01    05 05 00 03 82 01 01 00 27 8c cf e9 c7 3b be c0    6f e8 96 84 fb 9c 5c 5d 90 e4 77 db 8b 32 60 9b    65 d8 85 26 b5 ba 9f 1e de 64 4e 1f c6 c8 20 5b    09 9f ab a9 e0 09 34 45 a2 65 25 37 3d 7f 5a 6f    20 cc f9 fa f1 1d 8f 10 0c 02 3a c4 c9 01 76 96    be 9b f9 15 d8 39 d1 c5 03 47 76 b8 8a 8c 31 d6    60 d5 e4 8f db fa 3c c6 d5 98 28 f8 1c 8f 17 91    34 cb cb 52 7a d1 fb 3a 20 e4 e1 86 b1 d8 18 0f    be d6 87 64 8d c5 0a 25 42 51 ef b2 38 b8 e0 1d    d0 e1 fc e6 f4 af 46 ba ef c0 bf c5 b4 05 f5 94    75 0c fe a2 be 02 ba ea 86 5b f9 35 b3 66 f5 c5    8d 85 a1 1a 23 77 1a 19 17 54 13 60 9f 0b e1 b4    9c 28 2a f9 ae 02 34 6d 25 93 9c 82 a8 17 7b f1    85 b0 d3 0f 58 e1 fb b1 fe 9c a1 a3 e8 fd c9 3f    f4 d7 71 dc bd 8c a4 19 e0 21 23 23 55 13 8f a4    16 02 09 7e b9 af ee db 53 64 bd 71 2f b9 39 ce    30 b7 b4 bc 54 e0 47 07 00 03 81 30 82 03 7d 30    82 02 e6 a0 03 02 01 02 02 03 12 bb e6 30 0d 06    09 2a 86 48 86 f7 0d 01 01 05 05 00 30 4e 31 0b    30 09 06 03 55 04 06 13 02 55 53 31 10 30 0e 06    03 55 04 0a 13 07 45 71 75 69 66 61 78 31 2d 30    2b 06 03 55 04 0b 13 24 45 71 75 69 66 61 78 20    53 65 63 75 72 65 20 43 65 72 74 69 66 69 63 61    74 65 20 41 75 74 68 6f 72 69 74 79 30 1e 17 0d    30 32 30 35 32 31 30 34 30 30 30 30 5a 17 0d 31    38 30 38 32 31 30 34 30 30 30 30 5a 30 42 31 0b    30 09 06 03 55 04 06 13 02 55 53 31 16 30 14 06    03 55 04 0a 13 0d 47 65 6f 54 72 75 73 74 20 49    6e 63 2e 31 1b 30 19 06 03 55 04 03 13 12 47 65    6f 54 72 75 73 74 20 47 6c 6f 62 61 6c 20 43 41    30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01    01 05 00 03 82 01 0f 00 30 82 01 0a 02 82 01 01    00 da cc 18 63 30 fd f4 17 23 1a 56 7e 5b df 3c    6c 38 e4 71 b7 78 91 d4 bc a1 d8 4c f8 a8 43 b6    03 e9 4d 21 07 08 88 da 58 2f 66 39 29 bd 05 78    8b 9d 38 e8 05 b7 6a 7e 71 a4 e6 c4 60 a6 b0 ef    80 e4 89 28 0f 9e 25 d6 ed 83 f3 ad a6 91 c7 98    c9 42 18 35 14 9d ad 98 46 92 2e 4f ca f1 87 43    c1 16 95 57 2d 50 ef 89 2d 80 7a 57 ad f2 ee 5f    6b d2 00 8d b9 14 f8 14 15 35 d9 c0 46 a3 7b 72    c8 91 bf c9 55 2b cd d0 97 3e 9c 26 64 cc df ce    83 19 71 ca 4e e6 d4 d5 7b a9 19 cd 55 de c8 ec    d2 5e 38 53 e5 5c 4f 8c 2d fe 50 23 36 fc 66 e6    cb 8e a4 39 19 00 b7 95 02 39 91 0b 0e fe 38 2e    d1 1d 05 9a f6 4d 3e 6f 0f 07 1d af 2c 1e 8f 60    39 e2 fa 36 53 13 39 d4 5e 26 2b db 3d a8 14 bd    32 eb 18 03 28 52 04 71 e5 ab 33 3d e1 38 bb 07    36 84 62 9c 79 ea 16 30 f4 5f c0 2b e8 71 6b e4    f9 02 03 01 00 01 a3 81 f0 30 81 ed 30 1f 06 03    55 1d 23 04 18 30 16 80 14 48 e6 68 f9 2b d2 b2    95 d7 47 d8 23 20 10 4f 33 98 90 9f d4 30 1d 06    03 55 1d 0e 04 16 04 14 c0 7a 98 68 8d 89 fb ab    05 64 0c 11 7d aa 7d 65 b8 ca cc 4e 30 0f 06 03    55 1d 13 01 01 ff 04 05 30 03 01 01 ff 30 0e 06    03 55 1d 0f 01 01 ff 04 04 03 02 01 06 30 3a 06    03 55 1d 1f 04 33 30 31 30 2f a0 2d a0 2b 86 29    68 74 74 70 3a 2f 2f 63 72 6c 2e 67 65 6f 74 72    75 73 74 2e 63 6f 6d 2f 63 72 6c 73 2f 73 65 63    75 72 65 63 61 2e 63 72 6c 30 4e 06 03 55 1d 20    04 47 30 45 30 43 06 04 55 1d 20 00 30 3b 30 39    06 08 2b 06 01 05 05 07 02 01 16 2d 68 74 74 70    73 3a 2f 2f 77 77 77 2e 67 65 6f 74 72 75 73 74    2e 63 6f 6d 2f 72 65 73 6f 75 72 63 65 73 2f 72    65 70 6f 73 69 74 6f 72 79 30 0d 06 09 2a 86 48    86 f7 0d 01 01 05 05 00 03 81 81 00 76 e1 12 6e    4e 4b 16 12 86 30 06 b2 81 08 cf f0 08 c7 c7 71    7e 66 ee c2 ed d4 3b 1f ff f0 f0 c8 4e d6 43 38    b0 b9 30 7d 18 d0 55 83 a2 6a cb 36 11 9c e8 48    66 a3 6d 7f b8 13 d4 47 fe 8b 5a 5c 73 fc ae d9    1b 32 19 38 ab 97 34 14 aa 96 d2 eb a3 1c 14 08    49 b6 bb e5 91 ef 83 36 eb 1d 56 6f ca da bc 73    63 90 e4 7f 7b 3e 22 cb 3d 07 ed 5f 38 74 9c e3    03 50 4e a1 af 98 ee 61 f2 84 3f 12".replace(/\s/g, "");
			var sctrace2 = "0b 00 03 f1 00 03 ee 00 03 eb 30 82 03 e7 30 82    02 cf a0 03 02 01 02 02 09 00 b9 ee d4 d9 55 a5    9e b3 30 0d 06 09 2a 86 48 86 f7 0d 01 01 05 05    00 30 70 31 0b 30 09 06 03 55 04 06 13 02 55 4b    31 16 30 14 06 03 55 04 0a 0c 0d 4f 70 65 6e 53    53 4c 20 47 72 6f 75 70 31 22 30 20 06 03 55 04    0b 0c 19 46 4f 52 20 54 45 53 54 49 4e 47 20 50    55 52 50 4f 53 45 53 20 4f 4e 4c 59 31 25 30 23    06 03 55 04 03 0c 1c 4f 70 65 6e 53 53 4c 20 54    65 73 74 20 49 6e 74 65 72 6d 65 64 69 61 74 65    20 43 41 30 1e 17 0d 31 31 31 32 30 38 31 34 30    31 34 38 5a 17 0d 32 31 31 30 31 36 31 34 30 31    34 38 5a 30 64 31 0b 30 09 06 03 55 04 06 13 02    55 4b 31 16 30 14 06 03 55 04 0a 0c 0d 4f 70 65    6e 53 53 4c 20 47 72 6f 75 70 31 22 30 20 06 03    55 04 0b 0c 19 46 4f 52 20 54 45 53 54 49 4e 47    20 50 55 52 50 4f 53 45 53 20 4f 4e 4c 59 31 19    30 17 06 03 55 04 03 0c 10 54 65 73 74 20 53 65    72 76 65 72 20 43 65 72 74 30 82 01 22 30 0d 06    09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f    00 30 82 01 0a 02 82 01 01 00 f3 84 f3 92 36 dc    b2 46 ca 66 7a e5 29 c5 f3 49 28 22 d3 b9 fe e0    de e4 38 ce ee 22 1c e9 91 3b 94 d0 72 2f 87 85    59 4b 66 b1 c5 f5 7a 85 5d c2 0f d3 2e 29 58 36    cc 48 6b a2 a2 b5 26 ce 67 e2 47 b6 df 49 d2 3f    fa a2 10 b7 c2 97 44 7e 87 34 6d 6d f2 8b b4 55    2b d6 21 de 53 4b 90 ea fd ea f9 38 35 2b f4 e6    9a 0e f6 bb 12 ab 87 21 c3 2f bc f4 06 b8 8f 8e    10 07 27 95 e5 42 cb d1 d5 10 8c 92 ac ee 0f dc    23 48 89 c9 c6 93 0c 22 02 e7 74 e7 25 00 ab f8    0f 5c 10 b5 85 3b 66 94 f0 fb 4d 57 06 55 21 22    25 db f3 aa a9 60 bf 4d aa 79 d1 ab 92 48 ba 19    8e 12 ec 68 d9 c6 ba df ec 5a 1c d8 43 fe e7 52    c9 cf 02 d0 c7 7f c9 7e b0 94 e3 53 44 58 0b 2e    fd 29 74 b5 06 9b 5c 44 8d fb 32 75 a4 3a a8 67    7b 87 32 0a 50 8d e1 a2 13 4a 25 af e6 1c b1 25    bf b4 99 a2 53 d3 a2 02 bf 11 02 03 01 00 01 a3    81 8f 30 81 8c 30 0c 06 03 55 1d 13 01 01 ff 04    02 30 00 30 0e 06 03 55 1d 0f 01 01 ff 04 04 03    02 05 e0 30 2c 06 09 60 86 48 01 86 f8 42 01 0d    04 1f 16 1d 4f 70 65 6e 53 53 4c 20 47 65 6e 65    72 61 74 65 64 20 43 65 72 74 69 66 69 63 61 74    65 30 1d 06 03 55 1d 0e 04 16 04 14 82 bc cf 00    00 13 d1 f7 39 25 9a 27 e7 af d2 ef 20 1b 6e ac    30 1f 06 03 55 1d 23 04 18 30 16 80 14 36 c3 6c    88 e7 95 fe b0 bd ec ce 3e 3d 86 ab 21 81 87 da    da 30 0d 06 09 2a 86 48 86 f7 0d 01 01 05 05 00    03 82 01 01 00 a9 bd 4d 57 40 74 fe 96 e9 2b d6    78 fd b3 63 cc f4 0b 4d 12 ca 5a 74 8d 9b f2 61    e6 fd 06 11 43 84 fc 17 a0 ec 63 63 36 b9 9e 36    6a b1 02 5a 6a 5b 3f 6a a1 ea 05 65 ac 7e 40 1a    48 65 88 d1 39 4d d3 4b 77 e9 c8 bb 2b 9e 5a f4    08 34 39 47 b9 02 08 31 9a f1 d9 17 c5 e9 a6 a5    96 4b 6d 40 a9 5b 65 28 cb cb 00 03 82 63 37 d3    ad b1 96 3b 76 f5 17 16 02 7b bd 53 53 46 72 34    d6 08 64 9d bb 43 fb 64 b1 49 07 77 09 61 7a 42    17 11 30 0c d9 27 5c f5 71 b6 f0 18 30 f3 7e f1    85 3f 32 7e 4a af b3 10 f7 6c c6 85 4b 2d 27 ad    0a 20 5c fb 8d 19 70 34 b9 75 5f 7c 87 d5 c3 ec    93 13 41 fc 73 03 b9 8d 1a fe f7 26 86 49 03 a9    c5 82 3f 80 0d 29 49 b1 8f ed 24 1b fe cf 58 90    46 e7 a8 87 d4 1e 79 ef 99 6d 18 9f 3e 8b 82 07    c1 43 c7 e0 25 b6 f1 d3 00 d7 40 ab 4b 7f 2b 7a    3e a6 99 4c 54".replace(/\s/g, "");
			testMessage(sctrace1, formats.parseCertificate, formats.certificateBytes, printCertificate);
			testMessage(sctrace2, formats.parseCertificate, formats.certificateBytes, printCertificate);
			var scrtrace1 = "0d 00 00 28 05 03 04 01 02 40 00 1e 06 01 06 02    06 03 05 01 05 02 05 03 04 01 04 02 04 03 03 01    03 02 03 03 02 01 02 02 02 03 00 00".replace(/\s/g, "");
			var scrtrace2 = "0d 00 05 5d 03 01 02 40 00 12 02 01 02 02 02 03    04 01 04 02 04 03 05 01 05 02 05 03 05 43 00 bd    30 81 ba 31 0b 30 09 06 03 55 04 06 13 02 55 53    31 13 30 11 06 03 55 04 08 13 0a 43 61 6c 69 66    6f 72 6e 69 61 31 11 30 0f 06 03 55 04 07 13 08    53 61 6e 20 4a 6f 73 65 31 15 30 13 06 03 55 04    0a 13 0c 50 61 79 50 61 6c 2c 20 49 6e 63 2e 31    25 30 23 06 03 55 04 0b 13 1c 43 6c 69 65 6e 74    20 43 65 72 74 69 66 69 63 61 74 65 20 41 75 74    68 6f 72 69 74 79 31 21 30 1f 06 03 55 04 03 13    18 50 61 79 50 61 6c 20 4c 69 76 65 20 43 6c 69    65 6e 74 20 43 41 20 76 32 31 22 30 20 06 09 2a    86 48 86 f7 0d 01 09 01 16 13 70 63 68 75 2d 63    61 32 40 70 61 79 70 61 6c 2e 63 6f 6d 00 9c 30    81 99 31 0b 30 09 06 03 55 04 06 13 02 55 53 31    13 30 11 06 03 55 04 08 13 0a 43 61 6c 69 66 6f    72 6e 69 61 31 11 30 0f 06 03 55 04 07 13 08 53    61 6e 20 4a 6f 73 65 31 15 30 13 06 03 55 04 0a    13 0c 50 61 79 50 61 6c 2c 20 49 6e 63 2e 31 13    30 11 06 03 55 04 0b 14 0a 6c 69 76 65 5f 63 65    72 74 73 31 18 30 16 06 03 55 04 03 14 0f 6c 69    76 65 5f 63 61 6d 65 72 63 68 61 70 69 31 1c 30    1a 06 09 2a 86 48 86 f7 0d 01 09 01 16 0d 72 65    40 70 61 79 70 61 6c 2e 63 6f 6d 00 b2 30 81 af    31 0b 30 09 06 03 55 04 06 13 02 55 53 31 0b 30    09 06 03 55 04 08 13 02 43 41 31 11 30 0f 06 03    55 04 07 13 08 53 61 6e 20 4a 6f 73 65 31 14 30    12 06 03 55 04 0a 13 0b 50 61 79 50 61 6c 20 49    6e 63 2e 31 2c 30 2a 06 03 55 04 0b 13 23 4d 6f    62 69 6c 65 20 43 6c 69 65 6e 74 20 43 65 72 74    69 66 69 63 61 74 65 20 41 75 74 68 6f 72 69 74    79 31 1e 30 1c 06 03 55 04 03 13 15 50 61 79 50    61 6c 20 4c 69 76 65 20 43 6c 69 65 6e 74 20 43    41 31 1c 30 1a 06 09 2a 86 48 86 f7 0d 01 09 01    16 0d 72 65 40 70 61 79 70 61 6c 2e 63 6f 6d 00    9f 30 81 9c 31 0b 30 09 06 03 55 04 06 13 02 55    53 31 0b 30 09 06 03 55 04 08 13 02 43 41 31 11    30 0f 06 03 55 04 07 13 08 53 61 6e 20 4a 6f 73    65 31 14 30 12 06 03 55 04 0a 13 0b 50 61 79 50    61 6c 20 49 6e 63 2e 31 1e 30 1c 06 03 55 04 0b    13 15 43 65 72 74 69 66 69 63 61 74 65 20 41 75    74 68 6f 72 69 74 79 31 19 30 17 06 03 55 04 03    13 10 50 61 79 50 61 6c 20 4c 69 76 65 20 43 41    20 32 31 1c 30 1a 06 09 2a 86 48 86 f7 0d 01 09    01 16 0d 72 65 40 70 61 79 70 61 6c 2e 63 6f 6d    00 be 30 81 bb 31 0b 30 09 06 03 55 04 06 13 02    55 53 31 13 30 11 06 03 55 04 08 13 0a 43 61 6c    69 66 6f 72 6e 69 61 31 11 30 0f 06 03 55 04 07    13 08 53 61 6e 20 4a 6f 73 65 31 15 30 13 06 03    55 04 0a 13 0c 50 61 79 50 61 6c 2c 20 49 6e 63    2e 31 1b 30 19 06 03 55 04 0b 13 12 4c 69 76 65    20 47 65 6e 65 72 69 63 20 43 65 72 74 73 31 1b    30 19 06 03 55 04 03 13 12 4d 6f 62 69 6c 65 20    43 6c 69 65 6e 74 20 43 41 20 32 31 33 30 31 06    09 2a 86 48 86 f7 0d 01 09 01 16 24 44 4c 2d 50    50 2d 41 70 70 6c 69 63 61 74 69 6f 6e 53 65 63    75 72 69 74 79 40 70 61 79 70 61 6c 2e 63 6f 6d    00 b7 30 81 b4 31 0b 30 09 06 03 55 04 06 13 02    55 53 31 0b 30 09 06 03 55 04 08 13 02 43 41 31    11 30 0f 06 03 55 04 07 13 08 53 61 6e 20 4a 6f    73 65 31 15 30 13 06 03 55 04 0a 13 0c 50 61 79    50 61 6c 2c 20 49 6e 63 2e 31 1e 30 1c 06 03 55    04 0b 13 15 43 65 72 74 69 66 69 63 61 74 65 20    41 75 74 68 6f 72 69 74 79 31 19 30 17 06 03 55    04 03 13 10 50 61 79 50 61 6c 20 4c 69 76 65 20    43 41 20 32 31 33 30 31 06 09 2a 86 48 86 f7 0d    01 09 01 16 24 44 4c 2d 50 50 2d 41 70 70 6c 69    63 61 74 69 6f 6e 53 65 63 75 72 69 74 79 40 70    61 79 70 61 6c 2e 63 6f 6d 00 8c 30 81 89 31 20    30 1e 06 03 55 04 03 0c 17 43 72 79 70 74 6f 20    4d 67 74 20 50 72 6f 64 20 52 6f 6f 74 20 43 41    31 1a 30 18 06 03 55 04 0b 0c 11 50 61 79 50 61    6c 20 43 72 79 70 74 6f 20 4d 67 74 31 14 30 12    06 03 55 04 0a 0c 0b 50 61 79 50 61 6c 20 49 6e    63 2e 31 11 30 0f 06 03 55 04 07 0c 08 53 61 6e    20 4a 6f 73 65 31 13 30 11 06 03 55 04 08 0c 0a    43 61 6c 69 66 6f 72 6e 69 61 31 0b 30 09 06 03    55 04 06 13 02 55 53 00 88 30 81 85 31 1c 30 1a    06 03 55 04 03 0c 13 4d 65 72 63 68 61 6e 74 20    49 73 73 75 69 6e 67 20 43 41 31 1a 30 18 06 03    55 04 0b 0c 11 50 6c 61 74 66 6f 72 6d 20 53 65    63 75 72 69 74 79 31 14 30 12 06 03 55 04 0a 0c    0b 50 61 79 50 61 6c 20 49 6e 63 2e 31 11 30 0f    06 03 55 04 07 0c 08 53 61 6e 20 4a 6f 73 65 31    13 30 11 06 03 55 04 08 0c 0a 43 61 6c 69 66 6f    72 6e 69 61 31 0b 30 09 06 03 55 04 06 13 02 55    53".replace(/\s/g, "");
			testMessage(scrtrace1, cr => formats.parseCertificateRequest(cr, formats.PV.TLS_1p2), cr => formats.certificateRequestBytes(cr, formats.PV.TLS_1p2), printCertificateRequest);
			testMessage(scrtrace2, cr => formats.parseCertificateRequest(cr, formats.PV.TLS_1p2), cr => formats.certificateRequestBytes(cr, formats.PV.TLS_1p2), printCertificateRequest);
			var sketrace1 = "0c 00 02 12 00 84 10 83 46 48 b3 74 7a 60 bc fe    3b 77 a9 34 f2 70 da b4 5c da ae 7b 5f fe 3e 86    fa ab fa 2c bf a8 c4 31 09 8d e6 30 f0 1e e5 45    51 08 af 68 05 30 36 25 60 90 a1 8b 71 08 b1 51    ca fb de 98 e5 ad 86 6c 6a 7d 87 47 d7 2c ee 8a    d7 b4 e1 91 c8 fb d4 97 ac 8c e8 3d c1 14 a9 70    c8 c8 68 e3 24 3f 24 3e 08 62 83 ee 29 23 5e 4e    a5 39 a6 4c b4 87 1a 33 be 9b e1 37 c2 cb 9b f5    62 6b c9 dd d4 3e 88 de a9 63 00 42 41 04 7a 7f    4c 86 e8 36 e6 d4 80 bc 28 98 16 29 84 4e c1 13    e8 6b 4b 84 db 74 fe 8e 81 20 28 17 5a f9 5a 34    9f 4f 40 05 6b c3 0b 4e 04 03 12 c9 29 66 22 95    db f8 3e 8b 27 52 8d 23 22 4d 55 89 be b6 00 42    41 04 7a 7f 4c 86 e8 36 e6 d4 80 bc 28 98 16 29    84 4e c1 13 e8 6b 4b 84 db 74 fe 8e 81 20 28 17    5a f9 5a 34 9f 4f 40 05 6b c3 0b 4e 04 03 12 c9    29 66 22 95 db f8 3e 8b 27 52 8d 23 22 4d 55 89    be b6 06 01 01 00 68 4f ec e3 7b df d4 ee dd 36    04 d1 0a ef af b7 48 02 c4 2d c0 a9 f7 6b db e5    35 bd 8e b3 ad 03 ce 4b 62 d7 6d 77 c7 35 a0 8d    19 12 9e 4f c2 e6 98 4f da 2a 07 5f c1 14 1c 08    dd cc c6 75 78 50 18 93 5d d1 42 75 5c 5f 61 11    de 84 3e 86 73 d2 d1 1c ae 23 6a f9 bd 53 76 eb    74 f6 a4 ca 5f 5c 9b 70 58 a8 0a 79 57 67 23 9e    aa de b0 19 87 30 b3 7c 03 7b 54 ca 32 a6 a9 5b    af 19 7c ad 74 2b 96 46 80 31 3f ce 30 30 a7 7c    41 4d c7 f0 da ca b6 5a 14 7c fe 22 02 c3 4f f7    c3 3a 73 74 0a 4a de cf 88 21 c4 cb ae 54 7a 84    5f 6d cb 54 c5 a1 7c be 8b 96 61 39 19 1d 9e d3    b6 14 72 2a 0b 4c 4d 54 fc 22 a1 c2 83 9a 5f ea    ff 03 75 7c 43 06 f6 34 cd 46 f8 1f 10 d7 61 a8    6b 6a b9 13 82 c3 8f 83 fb 04 c7 60 11 2b 33 ad    b6 58 98 54 59 3f 12 23 76 6b 29 1d 57 7f 4e 16    db e3 87 8f d1 f9".replace(/\s/g, "");
			var sketrace2 = "0c 00 01 49 03 00 17 41 04 7c 7a e7 6f 1f 98 f0    fb 8d 76 10 bb 35 5d d5 fb ae 45 12 ce a9 d1 53    67 fd 02 f9 94 e7 70 31 18 34 d0 dd 83 0f 6a 6e    c5 4a c0 ec bc 1c 26 a0 6a e5 22 50 6a 62 31 a9    eb 15 69 c2 02 75 cb 45 fc 06 01 01 00 6b b4 bb    f2 24 29 c9 70 ee 6b 8f a5 1b 5d 96 e4 54 fc b7    90 f9 28 69 c7 5b 1f a8 86 6f 3d 9f c7 a5 77 b8    d6 f7 54 e0 1b bb c0 a7 8e 03 2e 06 c2 4d 9c cd    3e 93 eb bd fe e1 f7 06 1d 86 a3 00 7a f8 c0 bd    c5 cd ec d7 76 04 16 bb 15 7e 9f af 03 39 2d 81    fd 21 ef e7 28 5e 6f c4 41 0b 7c 6e 91 86 a5 02    3e fc ae 68 4f 0e 70 9b 31 9e a2 42 b9 d8 c8 7b    f0 2f b3 f5 d6 ba 96 e0 f7 78 3a e9 2a 16 2e 64    ae 75 28 38 a4 78 45 f5 ab 3f 5b 28 71 6c bd 43    b4 35 bc 67 4b da 05 18 9e 49 9e 22 d7 4d 8e f7    33 2a fc 1f 74 d2 8e ce 62 d1 5c 5e 0e d6 45 e1    34 92 62 a9 ca 4d 21 59 b6 1c b0 c0 76 a1 cf dd    eb d0 08 17 6c 26 52 06 56 06 a5 b3 d0 1a 96 68    e9 d0 6e 83 0c fe 7a 98 c9 fc 1a e8 36 ee b5 d1    3a 13 07 de de 77 17 1e af 4e ef d0 9f ae d9 34    e3 66 e1 8b 17 16 80 6b ef 33 60 75 fe".replace(/\s/g, "");
			testMessage(sketrace1, ske => formats.parseServerKeyExchange(ske, formats.PV.TLS_1p2, "DHE"), ske => formats.serverKeyExchangeBytes(ske, formats.PV.TLS_1p2), printServerKeyExchange);
			testMessage(sketrace2, ske => formats.parseServerKeyExchange(ske, formats.PV.TLS_1p2, "ECDHE"), ske => formats.serverKeyExchangeBytes(ske, formats.PV.TLS_1p2), printServerKeyExchange);
			var cketrace1 = "10 00 00 42 41 04 44 c1 3e 68 b2 d9 ea 44 12 e8    24 18 de f8 8b 1d 99 32 ea 41 ed 0a 49 38 7f b0    47 4e b3 f2 2d a4 96 46 38 3e d6 10 24 4e ff 70    22 b0 51 14 72 cd 5e 5a aa 13 da f0 43 df dd ec    69 ea 32 49 6e d7".replace(/\s/g, "");
			var cketrace2 = "10 00 00 03 00 01 01".replace(/\s/g, "");
			var cke1 = formats.parseMessage(cketrace1).bind(msg => formats.parseClientKeyExchange(msg.fst.pl, formats.PV.TLS_1p2, "ECDHE"));
			testMessage(cketrace1, cke => formats.parseClientKeyExchange(cke, formats.PV.TLS_1p2, "ECDHE"), cke => formats.clientKeyExchangeBytes(cke, formats.PV.TLS_1p2), cke => cke);
			testMessage(cketrace2, cke => formats.parseClientKeyExchange(cke, formats.PV.TLS_1p2, "DHE"), cke => formats.clientKeyExchangeBytes(cke, formats.PV.TLS_1p2), cke => cke);
			/*
            var fs = require('fs');
            fs.readFile('log.hex', 'utf8', function(err, data) {
            if (err) {
            return console.log(err);
            }
            data = data.replace(/(\r\n|\r|\n|\s)/g, "");
            // var ch = mapResult2(formats.parseMessage(data),function(msg){return formats.parseClientHello(msg.fst.pl)});
            //console.log(JSON.stringify(mapResult(ch,printClientHello),null,'\t'));
             ////        console.log("len:"+data.length+",data[len-1]:"+data[data.length-1]);
            console.log(printLog(formats.parseLog(data, formats.PV.TLS_1p2, "DHE").fst.value))
            });
          */
			console.log("trying record");
			console.log(formats.serializeRecord({
						type: formats.ContentType.handshake,
						version: formats.PV.TLS_1p2,
						fragment: formats.clientHelloBytes(ch1.value)
			}));
			//var b = new Buffer(formats.serializeRecord({type:formats.ContentType.handshake,version:formats.PV.TLS_1p2,fragment:formats.clientHelloBytes(ch1.value)}),'hex');
			/* Testing NET */
}

function testKDF() {
			var ms = "4A 1A 51 2C 01 60 BC 02 3C CF BC 83 3F 03 BC 64 88 C1 31 2F 0B A9 A2 77 16 A8 D8 E8 BD C9 D2 29 38 4B 7A 85 BE 16 4D 27 33 D5 24 79 87 B1 C5 A2".toLowerCase().replace(/\s/g, "");
			var crand = "00 00 00 02 6A 66 43 2A 8D 14 43 2C EC 58 2D 2F C7 9C 33 64 BA 04 AD 3A 52 54 D6 A5 79 AD 1E 00".toLowerCase().replace(/\s/g, "");
			var srand = "3F FB 11 C4 6C BF A5 7A 54 40 DA E8 22 D3 11 D3 F7 6D E4 1D D9 33 E5 93 70 97 EB A9 B3 66 F4 2A".toLowerCase().replace(/\s/g, "");
			var label = "6b 65 79 20 65 78 70 61 6e 73 69 6f 6e".toLowerCase().replace(/\s/g, "");
			var expected = util.hexStringToByteArray("E73C1963DEF10AC57E89DA1655F233A96DE2A93836DDBC6C657F68A8B327CAE763ADF9C0532A8D4805A836F17F545D5047082831F3D5FE7EA4FEEA1FFB915FE940B89550D33CD38F3FBA04B05757C85AB63EF3CE8D6414434493A0CF6E9B481CD6B034A425A896F82009DD1AE7F47E62EED98AFF805CA177FA39C0823040B5C1D9DB319B8FF6B4AFA84AAE029E154A13D16AEFECA038DCA734B36430336BB548608909119D18019453AE20F40EEEDC2ABDC0B4401C9E9DACD4A8BECD335D548A45AA27F6D6CC311614566F02173EF8EA70D7245FB3CE2FC614F6BDA68C47A9AC266FE6EC112628CEE5D83A11E5ECCF7E6935D094C28E422071A1DF8678A3A966019CFB03CEBA8EE14BA2BDC4CA8B235CCB2E384F31397B7825E1469CD36CBEBB4D72B9E8998100E7C696AD63D0771CCA3A7E0567330CA5AF615A4989A17FCBFD5674D5262842DB8152FB73889099A7A68CC23266413837B0A2C9AC3B93B57CB9D11F00C3A4ECE39231D1AD5F358F321EF53456CF6C8B640157051F03BEB11388E70A2766B7817A340196A5D4448D16966AFE951F81494CBB2A566120DA1047E355815628DCBA8D595DABD914FD2232DFAC87A575FCA2D5B2F5CDB9C09CF134BDAEF33C7AC6DA810AA0EDBFD92A306BCA5A6C793EE72009BF0AFF109E52D54647AEC3646CCF925231D249EC264EE8603624C5E81ADA32D08669AC6A1531BE26B7");
			var vd = handshake.tls_prf(formats.PV.TLS_1p2, ms, label, crand + srand, 512);
			console.log("calculated: " + vd);
			console.log("expected: " + expected);
			console.log(vd == expected ? "equal!" : "not equal!");
}

/* End: tls-tests.js - unit tests */

module.exports = {
			printHandshakeMessage: printHandshakeMessage,
			printLog: printLog
};