/*  weak */

'use strict';

const stackTrace = require('stack-trace');
const fs = require('fs');
const net = require('net');
const util = require('./util.js');
const tls_crypto = require('./tls_crypto.js');
const formats = require('./tls_formats.js');
const pp = require('./tls_prettyprint.js');
const tls_core = require('./tls_core_protocol.js');
const Correct = formats.Correct;
const Incorrect = formats.Incorrect;
const AD = formats.AD;

const sessionKey = {
	k: util.hexStringToByteArray(tls_crypto.nonce(16)),
	n: util.hexStringToByteArray(tls_crypto.nonce(12))
};

const defaultConfig = {
	ver_min: formats.PV.TLS_1p0,
	ver_max: formats.PV.TLS_1p3,
	cipher_suites: [formats.CS.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, formats.CS.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, formats.CS.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, formats.CS.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, formats.CS.TLS_RSA_WITH_AES_128_GCM_SHA256, formats.CS.TLS_RSA_WITH_AES_128_CBC_SHA, formats.CS.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256, formats.CS.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256],
	groups: [formats.SG.secp256r1, formats.SG.ffdhe2048],
	sigalgs: [{
		hash_alg: formats.HA.sha256,
		sig_alg: formats.SA.rsa
	}, {
		hash_alg: formats.HA.sha1,
		sig_alg: formats.SA.rsa
	}],
	compressions: [formats.CM.null_compression]
};

const defaultKeys = function () {
	return {
		ae: "AES_128_GCM_SHA256",
		writeMacKey: '',
		readMacKey: '',
		writeIv: '',
		readIv: '',
		writeKey: '',
		readKey: '',
		writeSn: 0,
		readSn: 0
	};
};
const defaultParams = {
	pv: formats.PV.TLS_1p2,
	ae: "AES_128_GCM_SHA256",
	kex: "ECDHE",
	gn: "p256",
	cr: '',
	sr: '',
	gx: '',
	gy: '',
	ext_ms: false
};

const defaultCipherState = {
	config: defaultConfig,
	params: defaultParams,
	current: defaultKeys(),
	next: defaultKeys(),
	write: false,
	read: false,
	log: "",
	host: "",

	x: "",
	y: "",
	log0: "",
	keys0: defaultKeys(),
	expect_early_data: false,
	session: {},
	ch: formats.defaultClientHello('', ''),
	ms: "",
	finkeys: {}
};

const tls_prf = function (pv, secret, label, data, len) {
	if (pv === formats.PV.TLS_1p0 || pv === formats.PV.TLS_1p1) {
		return tls_crypto.tls10_prf(secret, label, data, len);
	}
	return tls_crypto.tls12_prf(secret, label, data, len);
};

const setClientKeys = function (keys, cip) {
	cip.ae = keys.ae;
	cip.writeMacKey = keys.writeMacKey;
	cip.readMacKey = keys.readMacKey;
	cip.writeKey = keys.writeKey;
	cip.readKey = keys.readKey;
	cip.writeIv = keys.writeIv;
	cip.readIv = keys.readIv;
	cip.readSn = 0;
	cip.writeSn = 0;
	return;
};
const setServerReadKeys = function (keys, cip) {
	cip.ae = keys.ae;
	cip.readMacKey = keys.writeMacKey;
	cip.readKey = keys.writeKey;
	cip.readIv = keys.writeIv;
	cip.readSn = 0;
	return;
};

const setServerKeys = function (keys, cip) {
	cip.ae = keys.ae;
	cip.writeMacKey = keys.readMacKey;
	cip.readMacKey = keys.writeMacKey;
	cip.writeKey = keys.readKey;
	cip.readKey = keys.writeKey;
	cip.writeIv = keys.readIv;
	cip.readIv = keys.writeIv;
	cip.readSn = 0;
	cip.writeSn = 0;
	return;
};

const clientDeriveKeys = function (params, ms, next) {
	const keys = tls_core.deriveKeys_12(params.ae, ms, params.sr + params.cr);
	setClientKeys(keys, next);
	return;
};
const serverDeriveKeys = function (params, ms, next) {
	const keys = tls_core.deriveKeys_12(params.ae, ms, params.sr + params.cr);
	setServerKeys(keys, next);
	return;
};

const handshakeRecord = function (cipherState, frag) {
	cipherState.log += frag;
	return {
		type: formats.ContentType.handshake,
		version: cipherState.params.pv,
		fragment: frag
	};
};

const encHandshakeRecord = function (cipherState, frag) {
	cipherState.log += frag;
	return {
		type: formats.ContentType.application_data,
		version: formats.PV.TLS_1p0,
		fragment: frag + formats.ContentType.handshake
	};
};

const ccsRecord = function (pv) {
	return {
		type: formats.ContentType.change_cipher_spec,
		version: pv,
		fragment: "01"
	};
};

const negotiate = function (cipherState, ch, sr) {
	var pv, cs;
	var sh = formats.defaultServerHello(sr);
	if (ch.protocol_version == formats.PV.TLS_1p3 && util.mem(formats.CS.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256, ch.cipher_suites) && ch.extensions[formats.EXT.pre_shared_key] != undefined) {
		var ticket = ch.extensions[formats.EXT.pre_shared_key][0].psk_identity;
		var dtick = tls_crypto.aes_gcm_decrypt(sessionKey.k, sessionKey.n, ticket, "");
		if (dtick.auth_ok) {
			var sess = JSON.parse(util.hex2a(dtick.plaintext));
			cipherState.session = sess;
			pv = formats.PV.TLS_1p3;
			cs = formats.CS.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256;
			sh.protocol_version = pv;
			sh.cipher_suite = cs;
			sh.extensions[formats.EXT.pre_shared_key] = {
				psk_identity: ticket
			};
			if (ch.extensions[formats.EXT.early_data] != undefined) {
				sh.extensions[formats.EXT.early_data] = "";
			}
			sh.extensions[formats.EXT.key_share] = {
				dh_group: formats.SG.secp256r1,
				dh_public: cipherState.params.gy
			};
			delete sh.extensions[formats.EXT.ec_point_format];
			delete sh.extensions[formats.EXT.renegotiation_info];
		} else throw Error("ticket not encrypted right");
	} else if (ch.protocol_version == formats.PV.TLS_1p3 && util.mem(formats.CS.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ch.cipher_suites)) {
		pv = formats.PV.TLS_1p3;
		cs = formats.CS.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
		sh.protocol_version = pv;
		sh.cipher_suite = cs;
		sh.extensions[formats.EXT.key_share] = {
			dh_group: formats.SG.secp256r1,
			dh_public: cipherState.params.gy
		};
		delete sh.extensions[formats.EXT.ec_point_format];
		delete sh.extensions[formats.EXT.renegotiation_info];
	} else if (ch.protocol_version == formats.PV.TLS_1p3 && util.mem(formats.CS.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, ch.cipher_suites)) {
		pv = formats.PV.TLS_1p3;
		cs = formats.CS.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256;
		sh.protocol_version = pv;
		sh.cipher_suite = cs;
		sh.extensions[formats.EXT.key_share] = {
			dh_group: formats.SG.ffdhe2048,
			dh_public: "02"
		};
		delete sh.extensions[formats.EXT.ec_point_format];
		delete sh.extensions[formats.EXT.renegotiation_info];
	} else if (ch.protocol_version == formats.PV.TLS_1p2 && util.mem(formats.CS.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ch.cipher_suites)) {
		pv = formats.PV.TLS_1p2;
		cs = formats.CS.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
		sh.protocol_version = pv;
		sh.cipher_suite = cs;
	} else if (ch.protocol_version == formats.PV.TLS_1p2 && util.mem(formats.CS.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, ch.cipher_suites)) {
		pv = formats.PV.TLS_1p2;
		cs = formats.CS.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256;
		sh.protocol_version = pv;
		sh.cipher_suite = cs;
	} else if (ch.protocol_version == formats.PV.TLS_1p2 && util.mem(formats.CS.TLS_RSA_WITH_AES_128_GCM_SHA256, ch.cipher_suites)) {
		pv = formats.PV.TLS_1p2;
		cs = formats.CS.TLS_RSA_WITH_AES_128_GCM_SHA256;
		sh.protocol_version = pv;
		sh.cipher_suite = cs;
	} else if (util.mem(ch.protocol_version, [formats.PV.TLS_1p0, formats.PV.TLS_1p1, formats.PV.TLS_1p2]) && util.mem(formats.CS.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ch.cipher_suites)) {
		pv = formats.PV.TLS_1p0;
		cs = formats.CS.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
		sh.protocol_version = pv;
		sh.cipher_suite = cs;
	} else if (util.mem(ch.protocol_version, [formats.PV.TLS_1p0, formats.PV.TLS_1p1, formats.PV.TLS_1p2]) && util.mem(formats.CS.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ch.cipher_suites)) {
		pv = formats.PV.TLS_1p0;
		cs = formats.CS.TLS_DHE_RSA_WITH_AES_128_CBC_SHA;
		sh.protocol_version = pv;
		sh.cipher_suite = cs;
	} else if (util.mem(ch.protocol_version, [formats.PV.TLS_1p0, formats.PV.TLS_1p1, formats.PV.TLS_1p2]) && util.mem(formats.CS.TLS_RSA_WITH_AES_128_CBC_SHA, ch.cipher_suites)) {
		pv = formats.PV.TLS_1p0;
		cs = formats.CS.TLS_RSA_WITH_AES_128_CBC_SHA;
		sh.protocol_version = pv;
		sh.cipher_suite = cs;
	} else {
		throw new Error("unsupported protocol version/ciphersuite");
	}
	cipherState.params.pv = pv;
	//    cipherState.cs = cs;
	cipherState.params.kex = formats.KEX(cs);
	cipherState.params.ae = formats.AE(pv, cs);
	cipherState.params.cr = ch.client_random;
	cipherState.params.sr = sh.server_random;
	return sh;
};

const validateNegotiation = function (cipherState, sh) {
	var ch = cipherState.ch;
	if (sh.protocol_version > ch.protocol_version) {
		throw new Error("server chose a greater version than client hello");
	}
	if (!util.mem(sh.cipher_suite, ch.cipher_suites)) {
		throw new Error("server chose a ciphersuite that was not in client hello");
	}
	if (sh.protocol_version !== formats.PV.TLS_1p3 && !util.mem(sh.compression, ch.compressions)) {
		throw new Error("server chose a compression method that was not in client hello");
	}
	cipherState.params.pv = sh.protocol_version;
	//    cipherState.cs = sh.cipher_suite;
	cipherState.params.cr = cipherState.ch.client_random;
	cipherState.params.sr = sh.server_random;
	cipherState.params.ae = formats.AE(cipherState.params.pv, sh.cipher_suite);
	cipherState.params.kex = formats.KEX(sh.cipher_suite);
};

const verifyData = function (pv, ms, label, log) {
	if (pv === formats.PV.TLS_1p2) {
		return tls_prf(pv, ms, util.a2hex(label), tls_crypto.sha256(log), 12);
	}
	return tls_prf(pv, ms, util.a2hex(label), tls_crypto.md5(log) + tls_crypto.sha1(log), 12);
};
const clientVerifyData = function (cipherState) {
	return verifyData(cipherState.params.pv, cipherState.ms, "client finished", cipherState.log);
};
const serverVerifyData = function (cipherState) {
	return verifyData(cipherState.params.pv, cipherState.ms, "server finished", cipherState.log);
};

const getLogHash = function (log, psk_ctx) {
	if (psk_ctx) return tls_crypto.sha256(log) + tls_crypto.sha256(psk_ctx);
	else return tls_crypto.sha256(log) + tls_crypto.sha256(util.zeroes(64));
};

const get_zero_rtt_keys = function (ss, log) {
	const zeroes = "0000000000000000000000000000000000000000000000000000000000000000";
	const hs_hash = getLogHash(log);
	const xSS = tls_crypto.hkdf_extract(zeroes, ss);
	const fink = tls_crypto.hkdf_expand_label(xSS, "client finished", "", 32);
	const hsk = tls_core.deriveKeys_13(xSS, "early handshake key expansion", hs_hash);
	const adk = tls_core.deriveKeys_13(xSS, "early application data key expansion", hs_hash);
	return {
		cfin: fink,
		htk: hsk,
		atk: adk
	};
};

const TLS_client_callbacks = {
	hs_send_client_hello: function (cipherState) {
		var pv = formats.PV.TLS_1p3;
		let sCH = tls_core.get_client_hello();
		let ch = formats.defaultClientHello(sCH.keys.p256.dh_public, sCH.cr);
		cipherState.params.cr = ch.client_random;
		cipherState.params.gx = sCH.keys.p256.dh_public;
		cipherState.x = sCH.keys.p256.dh_private;

		if (cipherState.session.pv == formats.PV.TLS_1p3) {
			ch.protocol_version = cipherState.session.pv;
			ch.cipher_suites = cipherState.config.cipher_suites;
			ch.extensions['000a'] = cipherState.config.groups;
			ch.extensions['000d'] = cipherState.config.sigalgs;
			ch.extensions['0029'] = [{
				psk_identity: cipherState.session.ticket
			}];
			ch.extensions['002a'] = {
				configuration_id: "",
				cipher_suite: formats.CS.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
				extensions: [],
				context: ""
			};
			ch.compressions = cipherState.config.compressions;
			cipherState.params.pv = pv;
			cipherState.ch = ch;

			//	    cipherState.SS = cipherState.session.rms;
			return [handshakeRecord(cipherState, formats.clientHelloBytes(ch))];
		} else {
			pv = formats.PV.TLS_1p0;
			ch.protocol_version = cipherState.config.ver_max;
			ch.cipher_suites = cipherState.config.cipher_suites;
			ch.extensions['000a'] = cipherState.config.groups;
			ch.extensions['000d'] = cipherState.config.sigalgs;
			ch.compressions = cipherState.config.compressions;
			cipherState.params.pv = pv;
			cipherState.ch = ch;
			return [handshakeRecord(cipherState, formats.clientHelloBytes(ch))];
		}
	},
	hs_send_client_finished0: function (cipherState) {
		/*	var hash = '';
  	var cf = formats.defaultFinished;
  	if (cipherState.session.pv == formats.PV.TLS_1p3) {
  	    cipherState.keys0 = get_zero_rtt_keys(cipherState.SS, cipherState.log);
  	    setClientKeys(cipherState.keys0.htk, cipherState);
  	    cipherState.params.pv = cipherState.session.pv;
  	    cipherState.ae = cipherState.session.ae;
  	    cipherState.write = true;
  	    hash = getLogHash(cipherState.log);
  	    cf.verify_data = tls_crypto.hmac_sha256(cipherState.keys0.cfin, hash);
  	    return [{
  		type: formats.ContentType.handshake,
  		version: cipherState.params.pv,
  		fragment: formats.finishedBytes(cf)
  	    }];
  	} else
  */
		return [];
	},
	app_data_send0: function (cipherState) {
		/*
  if (cipherState.session.pv == formats.PV.TLS_1p3) {
      setClientKeys(cipherState.keys0.atk, cipherState);
      return [{
  	type: formats.ContentType.application_data,
  	version: cipherState.params.pv,
  	fragment: (
  	    (util.a2hex('GET / HTTP/1.1')) +
  		'0d0a' +
  		(util.a2hex('Host: ' + cipherState.host)) +
  		'0d0a0d0a'
  	)
      },
  	    {
  		type: formats.ContentType.alert,
  		version: cipherState.params.pv,
  		fragment: AD.end_of_early_data
  	    }];
  		    }
  	    else */
		return [];
	},
	hs_recv_server_hello: function (msgs, cipherState) {
		if (msgs.length != 1) {
			throw new Error('first recd message not server hello: ' + pp.printLog(msgs));
		}
		var sh = msgs[0].pl;
		var es = '';
		const psk = sh.extensions['0029'];
		validateNegotiation(cipherState, sh);
		let ch_log = getLogHash(cipherState.log);
		cipherState.log += msgs[0].to_log;
		if (sh.protocol_version == formats.PV.TLS_1p3) {
			if (sh.extensions['0028'].dh_group == formats.SG.secp256r1) {
				cipherState.params.gy = sh.extensions['0028'].dh_public;
				cipherState.params.ext_ms = false;
				var rSH = tls_core.put_server_hello_13(cipherState.params.cr, cipherState.params, getLogHash(cipherState.log));

				setClientKeys(rSH, cipherState.current);
				cipherState.read = true;
				cipherState.write = true;
				/*
      clientHandshakeKeys(
      tls_crypto.p256r1_ecdh(
      cipherState.p256r1_keys.ec_private,
      sh.extensions['0028'].dh_public
      ),
      cipherState
      );
    */
			} else if (sh.extensions['0028'].dh_group == formats.SG.ffdhe2048) {
				/*
      clientHandshakeKeys(
      sh.extensions['0028'].dh_public, cipherState
      );
    */
				throw 'unsupported group' + new Error().stack;
			} else {
				throw 'unsupported group' + new Error().stack;
			}
		}
		if (sh.protocol_version == formats.PV.TLS_1p3 && psk != undefined) {
			if (cipherState.session.ticket != psk.psk_identity) {
				throw new Error('unexpected psk in server hello');
			}
			//	    cipherState.SS = cipherState.session.rms;
		} else {
			//	    cipherState.SS = cipherState.ES;
		}
		return [];
	},
	hs_recv_server_hello_done: function (msgs, cipherState) {
		var creq = false;
		var ch = cipherState.ch;
		var pms = '';
		var ms = '';
		var scert = msgs[0].pl.chain[0];
		var next = 2;
		var ske = '';
		var out_msgs = [];
		var cc = {
			chain: []
		};
		var cke = formats.defaultClientKeyExchange_RSA;
		var fin = formats.defaultFinished;
		if (msgs.length < 1 || msgs[0].ht != formats.HT.certificate) {
			throw new Error('second recd message not server cert: ' + pp.printLog(msgs));
		}
		cipherState.log += msgs[0].to_log;
		if (cipherState.params.kex == 'ECDHE') {
			if (msgs.length < 2 || msgs[1].ht != formats.HT.server_key_exchange || msgs[1].pl.kex != 'ECDHE' || msgs[1].pl.ec_params.curve != formats.SG.secp256r1) {
				throw new Error('third recd message in ECDHE not ske:' + pp.printLog(msgs));
			}
			ske = msgs[1].pl.ec_public;
			cipherState.log += msgs[1].to_log;
			next = 2;
		}
		if (cipherState.params.kex == 'DHE') {
			if (msgs.length < 2 || msgs[1].ht != formats.HT.server_key_exchange || msgs[1].pl.kex != 'DHE') {
				throw new Error('third recd message in DHE not ske:' + pp.printLog(msgs));
			}
			ske = msgs[1].pl.dh_public;
			cipherState.log += msgs[1].to_log;
			next = 2;
		}
		if (msgs.length == next + 2 && msgs[(next >>> 0) % msgs.length].ht == formats.HT.certificate_request && msgs[(next + 1 >>> 0) % msgs.length].ht == formats.HT.server_hello_done) {
			creq = true;
			cipherState.log += msgs[(next >>> 0) % msgs.length].to_log + msgs[(next + 1 >>> 0) % msgs.length].to_log;
		} else if (msgs.length == next + 1 && msgs[(next >>> 0) % msgs.length].ht == formats.HT.server_hello_done) {
			cipherState.log += msgs[(next >>> 0) % msgs.length].to_log;
		} else {
			throw new Error('unexpected messages:' + pp.printLog(msgs));
		}

		if (creq == true) {
			out_msgs.push(handshakeRecord(cipherState, formats.certificateBytes(cc, cipherState.params.pv)));
		}
		if (cipherState.params.kex == 'ECDHE') {
			out_msgs.push(handshakeRecord(cipherState, formats.clientKeyExchangeBytes(formats.defaultClientKeyExchange_ECDHE(cipherState.params.gx), cipherState.params.pv)));

			pms = tls_crypto.p256r1_ecdh(cipherState.x, ske);
		} else if (cipherState.params.kex == 'DHE') {
			out_msgs.push(handshakeRecord(cipherState, formats.clientKeyExchangeBytes(formats.defaultClientKeyExchange_DHE, cipherState.params.pv)));
			pms = ske;
		} else if (cipherState.params.kex == 'RSA') {
			pms = cipherState.config.ver_max + util.zeroes(92);
			cke.encpms = tls_crypto.rsa_encrypt(tls_crypto.cert_get_publicKey(scert), pms);
			out_msgs.push(handshakeRecord(cipherState, formats.clientKeyExchangeBytes(cke, cipherState.params.pv)));
		} else {
			throw new Error('only ecdhe/rsa supported');
		}
		cipherState.ms = tls_prf(cipherState.params.pv, pms, util.a2hex('master secret'), cipherState.params.cr + cipherState.params.sr, 48);
		clientDeriveKeys(cipherState.params, cipherState.ms, cipherState.next);
		out_msgs.push(ccsRecord(cipherState.params.pv));
		fin.verify_data = clientVerifyData(cipherState);
		out_msgs.push(handshakeRecord(cipherState, formats.finishedBytes(fin)));
		return out_msgs;
	},
	hs_recv_server_finished: function (msgs, cipherState) {
		var out_msgs = [];
		var fin_msg;
		if (cipherState.params.pv == formats.PV.TLS_1p3) {
			let scert = msgs[1].pl.chain[0];
			cipherState.log += msgs[0].to_log + msgs[1].to_log;
			let hash1 = getLogHash(cipherState.log);

			let spk = tls_crypto.cert_get_publicKey(scert);
			let sigval = '20202020202020202020202020202020' + '20202020202020202020202020202020' + '20202020202020202020202020202020' + '20202020202020202020202020202020' + util.a2hex("TLS 1.3, server CertificateVerify") + "00" + hash1;
			console.log("Checking server signature: " + tls_crypto.rsa_sha256_verify(spk, sigval, msgs[2].pl.sig.sig_value));

			cipherState.log += msgs[2].to_log;
			fin_msg = msgs[3];
			let hash2 = getLogHash(cipherState.log);

			//	    console.log("checking finished for hash:" + hash2);
			//	    console.log("got fin: " + fin_msg.pl.verify_data);
			//	    console.log("computed fin: " + tls_crypto.hmac_sha256(finkeys.sfin, hash2));

			cipherState.log += fin_msg.to_log;
			let hash3 = getLogHash(cipherState.log);

			let rSF = tls_core.put_server_finished_13(cipherState.params.cr, scert, hash1, msgs[2].pl.sig.sig_value, hash2, fin_msg.pl.verify_data, hash3);

			var cf = formats.defaultFinished;
			let rCF = tls_core.get_client_finished_no_auth_13(cipherState.params.cr, hash3);
			cf.verify_data = rCF.cfin;
			out_msgs.push(handshakeRecord(cipherState, formats.finishedBytes(cf)));
			setClientKeys(rSF, cipherState.next);
			cipherState.current.readMacKey = cipherState.next.readMacKey;
			cipherState.current.readKey = cipherState.next.readKey;
			cipherState.current.readIv = cipherState.next.readIv;
			cipherState.current.readSn = 0;
		}
		return out_msgs;
	},
	hs_recv_session_ticket: function (msg, cipherState) {
		const hs_hash = getLogHash(cipherState.log);
		const re = tls_core.put_session_ticket_13(cipherState.params.cr, hs_hash, msg.ticket);
		if (cipherState.params.pv == formats.PV.TLS_1p3) {
			cipherState.session = {
				pv: cipherState.params.pv,
				ae: cipherState.params.ae,
				rms: re.rms,
				lifetime: msg.lifetime,
				ticket: msg.ticket
			};
		}
	},
	app_data_send: function (msg, cipherState) {
		if (cipherState.params.pv == formats.PV.TLS_1p3) {
			cipherState.current.writeMacKey = cipherState.next.writeMacKey;
			cipherState.current.writeKey = cipherState.next.writeKey;
			cipherState.current.writeIv = cipherState.next.writeIv;
			cipherState.current.writeSn = 0;
		}
		return [{
			type: formats.ContentType.application_data,
			version: cipherState.params.pv,
			fragment: util.a2hex('GET / HTTP/1.1') + '0d0a' + util.a2hex('Host: ' + cipherState.host) + '0d0a0d0a'
		}];
	}
};

const TLS_server_callbacks = {
	hs_recv_client_hello: function (msgs, cipherState) {
		var ch = msgs[0];
		var sh = negotiate(cipherState, ch.pl, util.zeroes(64));
		if (ch.ht != formats.HT.client_hello || msgs.length != 1) {
			return [];
		}
		cipherState.log = ch.to_log;
		cipherState.log0 = ch.to_log;
		if (cipherState.params.pv == formats.PV.TLS_1p3) {
			var rCH = tls_core.put_client_hello_13(ch.client_random, ch.pl.extensions[formats.EXT.key_share][0].dh_public, getLogHash(cipherState.log));
			sh.server_random = rCH.sr;
			cipherState.params.sr = rCH.sr;
			cipherState.params.cr = ch.client_random;
			cipherState.params.gy = rCH.gy;
			cipherState.params.gx = ch.pl.extensions[formats.EXT.key_share][0].dh_public;
			sh.extensions[formats.EXT.key_share] = {
				dh_group: formats.SG.secp256r1,
				dh_public: cipherState.params.gy
			};
			const psk = sh.extensions[formats.EXT.pre_shared_key];
			if (psk != undefined) {
				cipherState.SS = cipherState.session.rms;
				if (ch.pl.extensions[formats.EXT.early_data] != undefined) {
					cipherState.keys0 = get_zero_rtt_keys(cipherState.SS, cipherState.log);
					cipherState.expect_early_data = true;
				} else cipherState.expect_early_data = false;
			} else cipherState.SS = cipherState.ES;
		}
		return [handshakeRecord(cipherState, formats.serverHelloBytes(sh))];
	},
	hs_send_server_hello_done: function (msgs, cipherState) {
		var out_msgs = [];
		var sc = formats.defaultServerCertificate;
		var ygy = tls_crypto.p256r1_keygen();
		cipherState.params.gy = ygy.ec_public;
		cipherState.params.y = ygy.ec_private;
		var ske = formats.defaultServerKeyExchange_ECDHE(cipherState.params.gy);
		out_msgs.push(handshakeRecord(cipherState, formats.certificateBytes(sc, cipherState.params.pv)));
		if (cipherState.params.kex == 'ECDHE') {
			ske.sign(cipherState.params.cr, cipherState.sr, cipherState.params.pv);
			out_msgs.push(handshakeRecord(cipherState, formats.serverKeyExchangeBytes(ske, cipherState.params.pv)));
		} else if (cipherState.params.kex == 'DHE') {
			ske = formats.defaultServerKeyExchange_DHE;
			ske.sign(cipherState.params.cr, cipherState.sr, cipherState.params.pv);
			out_msgs.push(handshakeRecord(cipherState, formats.serverKeyExchangeBytes(ske, cipherState.params.pv)));
		}
		out_msgs.push(handshakeRecord(cipherState, formats.serverHelloDoneBytes));
		return out_msgs;
	},
	hs_send_server_finished: function (msgs, cipherState) {
		var hash1 = getLogHash(cipherState.log);

		var out_msgs = [];
		out_msgs.push(handshakeRecord(cipherState, formats.encryptedExtensionsBytes()));
		var sc = formats.defaultServerCertificate;
		out_msgs.push(handshakeRecord(cipherState, formats.certificateBytes(sc, cipherState.params.pv)));
		var hash2 = getLogHash(cipherState.log);
		let params = {
			pv: cipherState.params.pv,
			kex: cipherState.params.kex,
			ae: cipherState.params.ae,
			cr: cipherState.params.cr,
			sr: cipherState.sr,
			gn: "p256",
			gy: cipherState.p256r1_keys.ec_public,
			gx: cipherState.peer_p256r1_public,
			ext_ms: false
		};
		var sCV = tls_core.get_server_certificate_verify_13(cipherState.sr, params, hash1, sc.chain, hash2);
		var scv = formats.defaultCertificateVerify;
		scv.sig.sig_value = sCV.sg;
		out_msgs.push(handshakeRecord(cipherState, formats.certificateVerifyBytes(scv, cipherState.params.pv)));

		var hash3 = getLogHash(cipherState.log);

		var sSF = tls_core.get_server_finished_13(cipherState.sr, hash3);

		var sf = formats.defaultFinished;
		sf.verify_data = sSF.sfin;

		out_msgs.push(handshakeRecord(cipherState, formats.finishedBytes(sf)));

		cipherState.hs_keys1 = sCV.keys;
		setServerKeys(cipherState.hs_keys1, cipherState.current);
		cipherState.write = true;
		cipherState.read = true;

		/*	if (cipherState.keys0) {
  	    setServerReadKeys(cipherState.keys0.htk, cipherState);
  	    cipherState.params.pv = cipherState.session.pv;
  	    cipherState.ae = cipherState.session.ae;
  	    cipherState.read = true;
  	}
  */
		return out_msgs;
	},
	hs_recv_client_ccs: function (msgs, cipherState) {
		var cke = msgs[0];
		var pms = '';
		if (cke.ht != formats.HT.client_key_exchange || msgs.length != 1) {
			// return [];
		}
		if (cipherState.params.kex == 'ECDHE') {
			pms = tls_crypto.p256r1_ecdh(cipherState.p256r1_keys.ec_private, cke.pl.ec_public);
		} else if (cipherState.params.kex == 'DHE') {
			pms = cke.pl.dh_public;
		} else if (cipherState.params.kex == 'RSA') {
			pms = tls_crypto.rsa_decrypt(tls_crypto.server_key_pem, cke.pl.encpms);
		} else {
			throw new Error('only ecdhe/rsa supported');
		}
		cipherState.ms = tls_prf(cipherState.params.pv, pms, util.a2hex('master secret'), cipherState.params.cr + cipherState.sr, 48);
		serverDeriveKeys(cipherState.params, cipherState.ms, cipherState.next);
		cipherState.log += cke.to_log;
		return [];
	},

	hs_recv_client_finished0: function (msgs, cipherState) {
		/*
  	if (cipherState.params.pv === formats.PV.TLS_1p3 &&
  	    cipherState.expect_early_data &&
  	    cipherState.keys0) {
  	    setServerKeys(cipherState.keys0.atk, cipherState);
  	    cipherState.read = true;
  	    var hash = getLogHash(cipherState.log0);
  	    var fin_msg = msgs[0];
  	    console.log('checking finished0 for hash:' + hash);
  	    console.log('got fin0: ' + fin_msg.pl.verify_data);
  	    console.log('computed fin0: ' + tls_crypto.hmac_sha256(cipherState.keys0.cfin, hash));
  	}
  */
		return [];
	},

	end_of_early_data_recv: function (cipherState) {
		/*	if (cipherState.params.pv === formats.PV.TLS_1p3 &&
  	    cipherState.expect_early_data &&
  	    cipherState.keys0) {
  	    cipherState.expect_early_data = false;
  	    setServerReadKeys(cipherState.hs_keys1, cipherState);
  	    cipherState.read = true;
  	}
  */
	},

	hs_recv_client_finished: function (msgs, cipherState) {
		if (cipherState.params.pv === formats.PV.TLS_1p3) {
			var cfin = msgs[0];

			if (cfin.ht != formats.HT.finished || msgs.length != 1) {
				return [];
			}

			let hash = getLogHash(cipherState.log);
			let x = tls_core.put_client_finished_no_auth_13(cipherState.sr, hash, cfin.pl.verify_data, "");

			setServerKeys(x, cipherState.next);
			cipherState.log += msgs[0].to_log;

			/*	    cipherState.session = {
   		pv: cipherState.params.pv,
   		ae: cipherState.ae,
   		rms: re.rms
   	    };
   */
			cipherState.current.readMacKey = cipherState.next.readMacKey;
			cipherState.current.readKey = cipherState.next.readKey;
			cipherState.current.readIv = cipherState.next.readIv;
			cipherState.current.readSn = 0;
			cipherState.current.writeMacKey = cipherState.next.writeMacKey;
			cipherState.current.writeKey = cipherState.next.writeKey;
			cipherState.current.writeIv = cipherState.next.writeIv;
			cipherState.current.writeSn = 0;
			return [];
		} else {
			var cfin = msgs[0];
			var rccs = ccsRecord(cipherState.params.pv);
			if (cfin.ht != formats.HT.finished || msgs.length != 1) {
				// return [];
			}
			cipherState.log += cfin.to_log;
			var fin = formats.defaultFinished;
			fin.verify_data = serverVerifyData(cipherState);
			var rfin = handshakeRecord(cipherState, formats.finishedBytes(fin));
			return [rccs, rfin];
		}
	},
	app_data_recv: function (msg, cipherState) {
		var out_msgs = [];
		if (cipherState.params.pv == formats.PV.TLS_1p3) {
			var ticket = {
				lifetime: "00000000",
				ticket: tls_crypto.aes_gcm_encrypt(sessionKey.k, sessionKey.n, util.a2hex(JSON.stringify(cipherState.session)), '')
			};
			var rtick = handshakeRecord(cipherState, formats.sessionTicketBytes(ticket, cipherState.params.pv));
			out_msgs.push(rtick);
		}
		var fsd = {
			type: formats.ContentType.application_data,
			version: cipherState.params.pv,
			fragment: util.a2hex('Hello') + '0d0a0d0a'
		};
		out_msgs.push(fsd);
		return out_msgs;
	}
};

module.exports = {
	TLS_client_callbacks: TLS_client_callbacks,
	TLS_server_callbacks: TLS_server_callbacks,
	defaultConfig: defaultConfig,
	defaultCipherState: defaultCipherState,
	handshakeRecord: handshakeRecord,
	tls_prf: tls_prf
};

/*


  const get_handshake_keys = function (es, log) {
  const zeroes = "0000000000000000000000000000000000000000000000000000000000000000";
  console.log(tls_crypto.sha256(zeroes));
  const hs_hash = getLogHash(log);
  const xES = tls_crypto.hkdf_extract(zeroes, es);
  const htk = deriveKeysHkdf(xES, "handshake key expansion", hs_hash);
  //            console.log("xes:"+xES + "\nlog:"+hs_hash+"\nhtk:"+ JSON.stringify(htk,'\t'));
  //            const mSS = tls_crypto.hkdf_expand_label(xSS, "expanded static secret", hs_hash, 32);
  //            console.log("xss:"+xSS + "\nlog:"+hs_hash+"\nexpanded static secret:"+ mSS);
  //            const mES = tls_crypto.hkdf_expand_label(xES, "expanded ephemeral secret", hs_hash, 32);
  //            console.log("xes:"+xES + "\nlog:"+hs_hash+"expanded ephemeral secret:"+ mSS);
  //            const ms = tls_crypto.hkdf_extract(mSS,mES);
  return (htk)
  }

  const get_finished_keys = function (ss, es, log) {
  const zeroes = "0000000000000000000000000000000000000000000000000000000000000000";
  const hs_hash = getLogHash(log);
  const xES = tls_crypto.hkdf_extract(zeroes, es);
  const xSS = tls_crypto.hkdf_extract(zeroes, ss);
  //            console.log("xes:"+xES + "\nlog:"+hs_hash+"\nhtk:"+ JSON.stringify(htk,'\t'));
  const mSS = tls_crypto.hkdf_expand_label(xSS, "expanded static secret", hs_hash, 32);
  //            console.log("xss:"+xSS + "\nlog:"+hs_hash+"\nexpanded static secret:"+ mSS);
  const mES = tls_crypto.hkdf_expand_label(xES, "expanded ephemeral secret", hs_hash, 32);
  //            console.log("xes:"+xES + "\nlog:"+hs_hash+"expanded ephemeral secret:"+ mSS);
  const ms = tls_crypto.hkdf_extract(mSS, mES);
  const cfin = tls_crypto.hkdf_expand_label(ms, "client finished", "", 32);
  const sfin = tls_crypto.hkdf_expand_label(ms, "server finished", "", 32);
  const ts0 = tls_crypto.hkdf_expand_label(ms, "application traffic secret", hs_hash, 32);
  return ({
  ts0: ts0,
  cfin: cfin,
  sfin: sfin,
  ms: ms
  })

  }


  const clientHandshakeKeys = function (es, cipherState) {
  var keys = get_handshake_keys(es, cipherState.log);
  setClientKeys(keys, cipherState);
  cipherState.ES = es;
  return;
  }

  const serverHandshakeKeys = function (es, cipherState) {
  var keys = get_handshake_keys(es, cipherState.log);
  setServerKeys(keys, cipherState);
  cipherState.ES = es;
  return;
  }

*/