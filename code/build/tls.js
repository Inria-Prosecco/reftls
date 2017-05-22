module.exports = function () {
	"use strict";

	const debug = false;
	const stackTrace = require('stack-trace');
	const fs = require('fs');
	const net = require('net');
	const util = require('./util.js');
	const tls_crypto = require('./tls_crypto.js');
	const formats = require('./tls_formats.js');
	const pp = require('./tls_prettyprint.js');
	const record = require('./tls_record.js');
	//	const typechecked = require('./tls_typechecked.js');
	const handshake = require('./tls_handshake.js');
	const Correct = formats.Correct;
	const Incorrect = formats.Incorrect;

	/* Test for the Skip-CCS attack by skipping the ServerCCS messsage */
	const Skip_CCS_server_callbacks = {
		hs_recv_client_hello: handshake.TLS_server_callbacks.hs_recv_client_hello,
		hs_recv_client_ccs: handshake.TLS_server_callbacks.hs_recv_client_ccs,
		hs_recv_client_finished: function (msgs, cipherState) {
			let out_msgs = handshake.TLS_server_callbacks.hs_recv_client_finished(msgs, cipherState);
			cipherState.require_alert = true;
			return [out_msgs[1]];
		}
	};
	/* Test for the Freak attack by sending an ephemeral RSA
     ServerKeyExchange during a standard RSA key exchange */
	const Freak_server_callbacks = {
		hs_recv_client_hello: function (msgs, cipherState) {
			let ch = msgs[0];
			if (ch.ht != formats.HT.client_hello || msgs.length != 1) {
				console.log("first msg not client hello:" + pp.printLog(msgs));
				return [];
			}
			if (ch.pl.protocol_version < formats.PV.TLS_1p0 || !util.mem(formats.CS.TLS_RSA_WITH_AES_128_CBC_SHA, ch.pl.cipher_suites)) {
				console.log("no TLS-RSA ciphersuite in client hello:" + pp.printLog(msgs));
				return [];
			}
			let pv = formats.PV.TLS_1p0;
			let cs = formats.CS.TLS_RSA_WITH_AES_128_CBC_SHA;
			let sh = formats.defaultServerHello(util.zeroes(64));
			sh.protocol_version = pv;
			sh.cipher_suite = cs;
			cipherState.pv = pv;
			cipherState.cs = cs;
			cipherState.kex = formats.KEX(cs);
			cipherState.alg = formats.AE(pv, cs);
			cipherState.cr = ch.pl.client_random;
			cipherState.sr = sh.server_random;
			let out_msgs = [];
			cipherState.log = ch.to_log;
			out_msgs.push(handshake.handshakeRecord(cipherState, formats.serverHelloBytes(sh)));
			let sc = formats.defaultServerCertificate;
			out_msgs.push(handshake.handshakeRecord(cipherState, formats.certificateBytes(sc, pv)));
			let ske = formats.defaultServerKeyExchange_RSA;
			ske.sign(cipherState.cr, cipherState.sr, cipherState.pv);
			out_msgs.push(handshake.handshakeRecord(cipherState, formats.serverKeyExchangeBytes(ske, cipherState.pv)));
			out_msgs.push(handshake.handshakeRecord(cipherState, formats.serverHelloDoneBytes));
			cipherState.require_alert = true;
			return out_msgs;
		}
	};
	/* Test for the MD5 downgrade attack by sending a ServerKeyExchange
     signed with RSA-MD5 */
	const MD5_downgrade_server_callbacks = {
		hs_recv_client_hello: function (msgs, cipherState) {
			let ch = msgs[0];
			if (ch.ht != formats.HT.client_hello || msgs.length != 1) {
				console.log("first msg not client hello:" + pp.printLog(msgs));
				return [];
			}
			if (ch.pl.protocol_version < formats.PV.TLS_1p2 || !util.mem(formats.CS.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ch.pl.cipher_suites)) {
				console.log("no TLS 1.2 ECDHE ciphersuite in client hello:" + pp.printLog(msgs));
				return [];
			}
			let pv = formats.PV.TLS_1p2;
			let cs = formats.CS.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
			let sh = formats.defaultServerHello(util.zeroes(64));
			sh.protocol_version = pv;
			sh.cipher_suite = cs;
			cipherState.pv = pv;
			cipherState.cs = cs;
			cipherState.kex = formats.KEX(cs);
			cipherState.alg = formats.AE(pv, cs);
			cipherState.cr = ch.pl.client_random;
			cipherState.sr = sh.server_random;
			let out_msgs = [];
			cipherState.log = ch.to_log;
			out_msgs.push(handshake.handshakeRecord(cipherState, formats.serverHelloBytes(sh)));
			let sc = formats.defaultServerCertificate;
			out_msgs.push(handshake.handshakeRecord(cipherState, formats.certificateBytes(sc, pv)));
			let ske = formats.defaultServerKeyExchange_ECDHE(cipherState.p256r1_keys.ec_public);
			ske.sig.sig_hash_alg = formats.SS.rsa_pkcs1_md5;
			ske.sign(cipherState.cr, cipherState.sr, cipherState.pv);
			out_msgs.push(handshake.handshakeRecord(cipherState, formats.serverKeyExchangeBytes(ske, cipherState.pv)));
			out_msgs.push(handshake.handshakeRecord(cipherState, formats.serverHelloDoneBytes));
			cipherState.require_alert = true;
			return out_msgs;
		}
	};
	const server_tests = {
		"freak": Freak_server_callbacks,
		"skip-ccs": Skip_CCS_server_callbacks,
		"md5-sig": MD5_downgrade_server_callbacks
	};
	const usage = function () {
		console.log("Usage: node tls.js client host port");
		console.log("or   : node tls.js server port");
		console.log("or   : node tls.js test-client host port");
		console.log("or   : node tls.js test-server [freak|skip-ccs|md5-sig] port");
	};
	if (process.argv.length <= 3) {
		usage();
	} else {
		let null_cb = function () {};
		if (process.argv[2] === 'server') {
			if (process.argv.length == 3) record.TLS_server_scenario(4443, null_cb);else record.TLS_server_scenario(parseInt(process.argv[3]), null_cb);
		} else if (process.argv[2] === 'client') {
			if (process.argv.length == 3) record.TLS_client_scenario("localhost", 4443, null_cb);else {
				//console.log(Date.now())
				record.TLS_client_scenario(process.argv[3], parseInt(process.argv[4]), null_cb);
			}
		} else if (process.argv[2] === 'client_resume') {
			let cb = function () {
				if (process.argv.length == 3) record.TLS_client_scenario("localhost", 4443, null_cb);else record.TLS_client_scenario(process.argv[3], parseInt(process.argv[4]), null_cb);
			};
			if (process.argv.length == 3) record.TLS_client_scenario("localhost", 4443, cb);else record.TLS_client_scenario(process.argv[3], parseInt(process.argv[4]), cb);
		} else if (process.argv[2] === 'test-server') {
			if (process.argv.length < 4 || !util.mem(process.argv[3], ["freak", "skip-ccs", "md5-sig"])) {
				usage();
				return false;
			}
			if (process.argv.length == 4) {
				record.tls_server(4443, server_tests[process.argv[3]], null_cb);
			} else {
				record.tls_server(parseInt(process.argv[4]), server_tests[process.argv[3]], null_cb);
			}
		} else {
			console.log(process.argv[2]);
			usage();
		}
	}
	return {
		get: function (uri, cb) {
			record.TLS_client_scenario(uri, 443, function (res) {
				res = res.substring(res.search(/(\r\n|\r|\n){4}/) + 4);
				cb(res);
			});
		}
	};
	/* End: tls.js - main TLS protocol */
}();