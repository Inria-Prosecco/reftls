/* @flow */

'use strict';
const fs = require('fs');
const net = require('net');
const util = require('./util.js');
const tls_crypto = require('./tls_crypto.js');
const formats = require('./tls_formats.js');
const tls_pp = require('./tls_prettyprint.js');
const pp = require('./tls_prettyprint.js');
const tls_core = require('./tls_core_protocol.js');
const Correct = formats.Correct;
const Incorrect = formats.Incorrect;
const AD = formats.AD;

var Sessions: {[id:string]:bytes} = {}

const defaultConfig = function() : config {
    return ({
    ver_min: formats.PV.TLS_1p0,
    ver_max: formats.PV.TLS_1p3,
    cipher_suites: [
	formats.CS.TLS_AES_128_GCM_SHA256,
	formats.CS.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	formats.CS.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	formats.CS.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	formats.CS.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	formats.CS.TLS_RSA_WITH_AES_128_GCM_SHA256,
	formats.CS.TLS_RSA_WITH_AES_128_CBC_SHA,
	formats.CS.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
	formats.CS.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
    ],
    groups: [formats.SG.secp256r1, formats.SG.ffdhe2048],
    sigalgs: [formats.SS.rsa_pkcs1_sha256, formats.SS.rsa_pss_sha256], 
    compressions: [formats.CM.null_compression],
    })}



const defaultParams = function() :params  {
    return ({
	pv: formats.PV.TLS_1p2,
	 host: "localhost",
	 cs: formats.CS.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	 ae: "AES_128_GCM_SHA256",
	 kex: "ECDHE",
   gn: "p256",
	 cr: '',
	 sr: '',
	 gx: '',
	 gy: '',
	ext_ms: false})}

const defaultCipherState = function() : cipher_state {
    return ({
	  role: "client",
	config: defaultConfig(),
	  host: "",
	params: defaultParams(),
	  server_certificate: [],
	  client_certificate: [],


  	ch: formats.defaultClientHello(defaultConfig(),'',{p256:"",ff2048:""}),
	  public_values: {p256:"",ff2048:""},

	  log: "",
	  log0: "",

	  write: false,
	  read: false,
	  write_keys: "",
	  read_keys: "",

	  expect_early_data: false,
	  ticket:"",
	  payload:"",
	  path:""
    })};

const handshakeRecord = function (pv:protocol_version, frag:string) : record {
    if (pv === formats.PV.TLS_1p3) pv = formats.PV.TLS_1p0;
    return ({
	type: formats.ContentType.handshake,
	version: pv,
	fragment: frag
    });
}

const ccsRecord = function (pv) : record {
    return ({
	type: formats.ContentType.change_cipher_spec,
	version: pv,
	fragment: "01"
    })
}

const negotiate = function (cipherState: cipher_state, ch:client_hello, sr:bytes32): server_hello {
    var pv, cs;
    var sh = formats.defaultServerHello(sr);
    let ch_pv = (ch.protocol_version === formats.PV.TLS_1p2 && util.mem("7f14",ch.extensions[formats.EXT.supported_versions])? formats.PV.TLS_1p3 : ch.protocol_version);
    if ((ch_pv == formats.PV.TLS_1p3) &&
	util.mem(formats.CS.TLS_AES_128_GCM_SHA256, ch.cipher_suites)) {
	pv = formats.PV.TLS_1p3;
	cs = formats.CS.TLS_AES_128_GCM_SHA256;
        sh.protocol_version = "7f14"; //NOTE: Will become == pv in final RFC
	sh.cipher_suite = cs;
	if (ch.extensions[formats.EXT.key_share][0].dh_group == formats.SG.secp256r1)
	    sh.extensions[formats.EXT.key_share] = {
		dh_group: formats.SG.secp256r1,
		dh_public: cipherState.params.gy
	    };
	else
	    if (ch.extensions[formats.EXT.key_share][0].dh_group == formats.SG.ffdhe2048)
		sh.extensions[formats.EXT.key_share] = {
		    dh_group: formats.SG.ffdhe2048,
		    dh_public: "02"
		};
	    else throw new Error("first key share must be p256/ff2048: fix nego");
	delete sh.extensions[formats.EXT.ec_point_format];
	delete sh.extensions[formats.EXT.renegotiation_info];

	if (ch.extensions[formats.EXT.pre_shared_key] != undefined) {
	    let ticket = ch.extensions[formats.EXT.pre_shared_key][0].psk_identity;
	    let sess = tls_core.getServerSession(ticket);
	    if (sess &&
		sess.params.pv === formats.PV.TLS_1p3 &&
		sess.params.cs === formats.CS.TLS_AES_128_GCM_SHA256)
		{
		    cipherState.ticket = ticket;
		    cipherState.params = sess.params;
		    cipherState.server_certificate = sess.cert;
		    sh.extensions[formats.EXT.pre_shared_key] = {
			psk_identity: ticket,
			obfuscated_ticket_age: "00000000"
		    };
		    if (ch.extensions[formats.EXT.early_data] != undefined) {
			sh.extensions[formats.EXT.early_data] = "";
		    }
		} else throw Error("ticket not encrypted right")
	     }
    } else if (
	(ch_pv == formats.PV.TLS_1p2) && util.mem(formats.CS.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
								ch.cipher_suites)) {
	pv = formats.PV.TLS_1p2;
	cs = formats.CS.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
	sh.protocol_version = pv;
	sh.cipher_suite = cs;
    } else if (
	(ch_pv == formats.PV.TLS_1p2) && util.mem(formats.CS.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
								ch.cipher_suites)) {
	pv = formats.PV.TLS_1p2;
	cs = formats.CS.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256;
	sh.protocol_version = pv;
	sh.cipher_suite = cs;
    } else if (
	(ch_pv == formats.PV.TLS_1p2) && util.mem(formats.CS.TLS_RSA_WITH_AES_128_GCM_SHA256,
								ch.cipher_suites)) {
	pv = formats.PV.TLS_1p2;
	cs = formats.CS.TLS_RSA_WITH_AES_128_GCM_SHA256;
	sh.protocol_version = pv;
	sh.cipher_suite = cs;
    } else if (util.mem(ch_pv, [
	formats.PV.TLS_1p0, formats.PV.TLS_1p1, formats.PV.TLS_1p2
    ]) && util.mem(formats.CS.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ch.cipher_suites)) {
	pv = formats.PV.TLS_1p0;
	cs = formats.CS.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
	sh.protocol_version = pv;
	sh.cipher_suite = cs;
    } else if (util.mem(ch_pv, [
	formats.PV.TLS_1p0, formats.PV.TLS_1p1, formats.PV.TLS_1p2
    ]) && util.mem(formats.CS.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ch.cipher_suites)) {
	pv = formats.PV.TLS_1p0;
	cs = formats.CS.TLS_DHE_RSA_WITH_AES_128_CBC_SHA;
	sh.protocol_version = pv;
	sh.cipher_suite = cs;
    } else if (util.mem(ch_pv, [
	formats.PV.TLS_1p0, formats.PV.TLS_1p1, formats.PV.TLS_1p2
    ]) && util.mem(formats.CS.TLS_RSA_WITH_AES_128_CBC_SHA, ch.cipher_suites)) {
	pv = formats.PV.TLS_1p0;
	cs = formats.CS.TLS_RSA_WITH_AES_128_CBC_SHA;
	sh.protocol_version = pv;
	sh.cipher_suite = cs;
    } else {
	throw new Error("unsupported protocol version/ciphersuite");
	}
    cipherState.params.host = cipherState.host;
    cipherState.params.pv = pv;
    cipherState.params.cs = cs;
    cipherState.params.kex = formats.KEX(cs);
    cipherState.params.ae = formats.AE(pv, cs);
    cipherState.params.cr = ch.client_random;
    cipherState.params.sr = sh.server_random;
    return sh;
}

const validateNegotiation = function (cipherState:cipher_state, sh:server_hello) {
    var ch = cipherState.ch;
    var sh_pv = (sh.protocol_version === "7f14"? formats.PV.TLS_1p3: sh.protocol_version);
    if (sh_pv > ch.protocol_version && !util.mem(sh_pv, ch.extensions[formats.EXT.supported_versions])) {
	throw new Error("server chose a version not offered in client hello");
    }
    if (!util.mem(sh.cipher_suite, ch.cipher_suites)) {
	throw new Error("server chose a ciphersuite that was not in client hello")
    }
    if (
	(sh_pv !== formats.PV.TLS_1p3) &&
	    !util.mem(sh.compression, ch.compressions)
    ) {
	throw new Error(
	    "server chose a compression method that was not in client hello"
	)
    }

    if (ch.protocol_version == formats.PV.TLS_1p3 &&
	ch.extensions[formats.EXT.pre_shared_key] != undefined &&
	ch.extensions[formats.EXT.pre_shared_key][0].psk_identity ===
	sh.extensions[formats.EXT.pre_shared_key].psk_identity) {
	cipherState.ticket = sh.extensions[formats.EXT.pre_shared_key].psk_identity;
    }

    cipherState.params.pv = sh_pv;
    cipherState.params.cs = sh.cipher_suite;
    cipherState.params.host = cipherState.host;
    cipherState.params.cr = cipherState.ch.client_random;
    cipherState.params.sr = sh.server_random;
    cipherState.params.ae = formats.AE(cipherState.params.pv, sh.cipher_suite);
    cipherState.params.kex = formats.KEX(sh.cipher_suite);
}

const getLogHash13 = function (log,psk_ctx) : bytes32{
  return tls_crypto.sha256(log);
  //    if (psk_ctx)
	//return (tls_crypto.sha256(log) + tls_crypto.sha256(psk_ctx))
  //  else return (tls_crypto.sha256(log) + tls_crypto.sha256(util.zeroes(64)))

}
const getLogHash12 = function (log) : bytes32{
    return tls_crypto.sha256(log)
}

const TLS_client_callbacks = {
    hs_send_client_hello: function (cipherState:cipher_state) : record[]{
	let sCH = tls_core.get_client_hello();
	let ch = formats.defaultClientHello(
	    cipherState.config, sCH.cr, sCH.public_values
	);
        ch.extensions[formats.EXT.server_name] = [{
	name_type: "00",
	host_name: util.a2hex(cipherState.host)
        }];

	cipherState.params.cr = ch.client_random;
        cipherState.params.pv = ch.protocol_version;
	cipherState.params.host = cipherState.host;
	cipherState.ch = ch;
	cipherState.public_values = sCH.public_values;
		/*
	if (cipherState.params.pv == formats.PV.TLS_1p3) {
		  if (cipherState.session.ticket) {
		  ch.extensions[formats.EXT.pre_share_key] = [{
		  psk_identity: cipherState.session.ticket
		  }];
		  ch.extensions[formats.EXT.early_data] = {
		  configuration_id: "",
		  cipher_suite: formats.CS.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
		  extensions: [],
		  context: ""
		  };
		  }
	}
		*/
	let chb = formats.clientHelloBytes(ch);
	cipherState.log += chb;
	let r:record = handshakeRecord(cipherState.params.pv, chb);
	return [r];

    },

    hs_send_client_finished0: function (cipherState:cipher_state): record[] {
    /*
	var hash = '';
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
    app_data_send0: function (cipherState:cipher_state) : record[]{
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
    hs_recv_server_hello: function (msgs:hs_msg[], cipherState:cipher_state) :record[]{
	let ch_log = getLogHash13(cipherState.log);
	if (msgs.length != 1 ||
	    msgs[0].ht !== formats.HT.server_hello) {
	    throw new Error('callback expected only serverhello, but got: ' + tls_pp.printLog(msgs));
	}
	let sh : server_hello = msgs[0].pl;
	validateNegotiation(cipherState, sh);
	cipherState.log += msgs[0].to_log;
	if (cipherState.params.pv === formats.PV.TLS_1p3) {
	    if (sh.extensions[formats.EXT.key_share].dh_group == formats.SG.secp256r1) {
		cipherState.params.gn = "p256";
		cipherState.params.gx = cipherState.public_values.p256;
		cipherState.params.gy = sh.extensions[formats.EXT.key_share].dh_public;
	    } else if (sh.extensions[formats.EXT.key_share].dh_group == formats.SG.ffdhe2048) {
		cipherState.params.gn = "ff2048";
		cipherState.params.gx = cipherState.public_values.ff2048;
		cipherState.params.gy = sh.extensions[formats.EXT.key_share].dh_public;
	    } else {
		throw ('unsupported group' + (new Error()).stack)
	    }
	    cipherState.params.ext_ms = false;
	    var rSH = tls_core.put_server_hello_13(
		cipherState.params.cr,
		cipherState.params,
		cipherState.ticket,
		getLogHash13(cipherState.log)
	    );
	    cipherState.read = true;
	    cipherState.write = true;
	    cipherState.read_keys = "clientHandshakeKeys";
	    cipherState.write_keys = "clientHandshakeKeys";
	}
	/*
	if (
	    (sh.protocol_version === formats.PV.TLS_1p3) &&
		(psk != undefined)
	) {
	    if (cipherState.session.ticket != psk.psk_identity) {
		throw new Error('unexpected psk in server hello');
	    }
	    cipherState.SS = cipherState.session.rms;
	} else {
	    cipherState.SS = cipherState.ES;
	}
	*/
	return [];
    },
    hs_recv_server_hello_done: function (msgs:hs_msg[], cipherState:cipher_state) : record[] {
	let out_msgs = [];
	let sh_log = getLogHash12(cipherState.log);
	switch (cipherState.params.kex) {
	case "ECDHE":
	    if (msgs.length === 3 &&
		cipherState.params.pv !== formats.PV.TLS_1p3 &&
		msgs[0].ht === formats.HT.certificate &&
	        msgs[1].ht === formats.HT.server_key_exchange &&
	        msgs[1].pl.kex === cipherState.params.kex &&
	        msgs[1].pl.ec_params.curve === formats.SG.secp256r1 &&
	        msgs[2].ht === formats.HT.server_hello_done) {
		cipherState.server_certificate = msgs[0].pl.chain;
		cipherState.params.gn = "p256";
		cipherState.params.gy = msgs[1].pl.ec_public;
		cipherState.params.gx = cipherState.public_values.p256;
		let dhp = formats.serverKeyExchangeParamsBytes(msgs[1].pl);
		cipherState.log += (msgs[0].to_log + msgs[1].to_log + msgs[2].to_log);
		let ckeb = formats.clientKeyExchangeBytes(
		    formats.defaultClientKeyExchange_ECDHE(
			cipherState.params.gx
		    ), cipherState.params.pv
		);
		cipherState.log += ckeb;
		out_msgs.push(handshakeRecord(cipherState.params.pv,ckeb));
		let fin = tls_core.put_server_hello_done_no_auth_12(cipherState.params.cr, cipherState.params,
								    msgs[0].pl.chain, dhp, msgs[1].pl.sig.sig_value,
								    getLogHash12(cipherState.log));
		let finb = formats.finishedBytes({verify_data:fin.cfin});
		cipherState.log += finb;
		cipherState.write_keys = "clientDataKeys";
		cipherState.read_keys = "clientDataKeys";
		out_msgs.push(ccsRecord(cipherState.params.pv));
		out_msgs.push(handshakeRecord(cipherState.params.pv,finb));
		return out_msgs;
	    }
	    else {throw new Error('only non-auth ecdhe 1.2 implemented 1: ' + tls_pp.printLog(msgs))}
	case "DHE": throw new Error('only ecdhe 1.2 implemented 2: ' + tls_pp.printLog(msgs))
	case "RSA": throw new Error('only ecdhe 1.2 implemented 3: ' + tls_pp.printLog(msgs))
	default: throw new Error('only ecdhe 1.2 implemented 4: ' + tls_pp.printLog(msgs))
	}
    },
    hs_recv_server_finished: function (msgs : hs_msg[], cipherState: cipher_state) : record[] {
	var fin_msg;
	if (cipherState.params.pv === formats.PV.TLS_1p3 &&
	    msgs.length === 4 &&
	    msgs[0].ht === formats.HT.encrypted_extensions &&
	    msgs[1].ht === formats.HT.certificate &&
	    msgs[2].ht === formats.HT.certificate_verify &&
	    msgs[3].ht === formats.HT.finished) {
	    cipherState.log += msgs[0].to_log + msgs[1].to_log;
	    let log1 = getLogHash13(cipherState.log);
	    cipherState.log += msgs[2].to_log;
	    let log2 = getLogHash13(cipherState.log);
	    cipherState.log += msgs[3].to_log;
	    let log3 = getLogHash13(cipherState.log);
	    let xxx = tls_core.put_server_finished_13(cipherState.params.cr, msgs[1].pl.chain, log1, msgs[2].pl.sig.sig_value, log2, msgs[3].pl.verify_data, log3);
	    let cfin = tls_core.get_client_finished_no_auth_13(cipherState.params.cr, log3);
	    let finb = formats.finishedBytes({verify_data:cfin.cfin});
	    cipherState.server_certificate = msgs[1].pl.chain;
	    cipherState.log += finb;
	    cipherState.read_keys = "clientDataKeys";
	    return [handshakeRecord(cipherState.params.pv,finb)];
	} else
	    if (cipherState.params.pv !== formats.PV.TLS_1p3 &&
		msgs.length === 1 &&
		msgs[0].ht === formats.HT.finished) {
		let res = tls_core.put_server_finished_no_auth_12(cipherState.params.cr, cipherState.ticket, getLogHash12(cipherState.log), msgs[0].pl.verify_data);
		if (res) Sessions[cipherState.host] = cipherState.ticket;
		else throw new Error('server finished failed in tls 1.2');
	    }
	else throw new Error('unexpected messages when server finished expected: ' + tls_pp.printLog(msgs));
	return []
    },
    hs_recv_session_ticket: function (msg : hs_msg, cipherState: cipher_state) : record[] {
	cipherState.ticket = msg.pl.ticket;
	if (cipherState.params.pv == formats.PV.TLS_1p3) {
	    const re = tls_core.put_session_ticket_13(cipherState.params.cr, getLogHash13(cipherState.log), cipherState.ticket);
     	    Sessions[cipherState.host] = cipherState.ticket;
	}
	else cipherState.log += msg.to_log;
	return []
    },
    app_data_send: function (msg : hs_msg[], cipherState: cipher_state) : record[] {
	if (cipherState.params.pv == formats.PV.TLS_1p3) {
	    cipherState.write_keys = "clientDataKeys";
	}
	console.log(cipherState.path)
	return [{
	    type: formats.ContentType.application_data,
	    version: cipherState.params.pv,
	    fragment: (
		(util.a2hex(`GET ${cipherState.path} HTTP/1.1`)) +
		    '0d0a' +
		    (util.a2hex('Host: ' + cipherState.host)) +
		    '0d0a0d0a'
	    )
	}]
    }
}

const getDHKey = function(keyshares,gn) {
    let i;
    for (i = 0; i<keyshares.length; i++)
	if (keyshares[i].dh_group === gn)
	    return keyshares[i].dh_public
    return undefined;
}

const TLS_server_callbacks = {
    hs_recv_client_hello: function (msgs: hs_msg[], cipherState: cipher_state): record[] {
	if (msgs.length === 1 &&
	    msgs[0].ht === formats.HT.client_hello) {
	    cipherState.log = msgs[0].to_log;
	    cipherState.log0 = msgs[0].to_log;
	    var ch = msgs[0].pl;
	    var sh = negotiate(cipherState, ch, util.zeroes(64));

	    if (cipherState.params.pv === formats.PV.TLS_1p3) {
		let p256key = getDHKey(ch.extensions[formats.EXT.key_share],
				       formats.SG.secp256r1);
		let ff2048key = getDHKey(ch.extensions[formats.EXT.key_share],
				       formats.SG.ffdhe2048);
		if (p256key) {
		    var rCH = tls_core.put_client_hello_13(
			ch.client_random,
			p256key,
			cipherState.ticket,
			getLogHash13(cipherState.log)
		    );
		    sh.server_random = rCH.sr;
		    cipherState.params.sr = rCH.sr;
		    cipherState.params.cr = ch.client_random;
		    cipherState.params.gn = "p256";
		    cipherState.params.gy = rCH.gy;
		    cipherState.params.gx = p256key;
      		    sh.extensions[formats.EXT.key_share] = {
			dh_group: formats.SG.secp256r1,
			dh_public: cipherState.params.gy
		    };
		}
		else throw new Error("only p256 supported currently");
		cipherState.read_keys = "serverHandshakeKeys";
		cipherState.read = true;
	    }
	    else {
		if (cipherState.params.kex === "ECDHE") {
		    var rCH = tls_core.put_client_hello_12(
			ch.client_random,
			tls_crypto.server_cert);
		    sh.server_random = rCH.sr;
		    cipherState.params.sr = rCH.sr;
		    cipherState.params.cr = ch.client_random;
		    cipherState.params.gn = "p256";
		    cipherState.params.gy = rCH.gy;
		}
		else throw new Error("only ECDHE supported currently")
	    }
	    let shb = formats.serverHelloBytes(sh);
	    cipherState.log += shb;
	    return [handshakeRecord(cipherState.params.pv, shb)]
	}
	else throw new Error("expected only client hello got: "+tls_pp.printLog(msgs))
     },
    hs_send_server_hello_done: function (msgs: hs_msg[], cipherState: cipher_state) : record[] {
	var sc = formats.defaultServerCertificate;

	if (cipherState.params.kex == 'ECDHE') {
	    var ske = formats.defaultServerKeyExchange_ECDHE(
		cipherState.params.gy
	    );
	    let dhp = formats.serverKeyExchangeParamsBytes(ske);
	    let res = tls_core.get_server_hello_done_12(cipherState.params.sr,dhp);
	    ske.sig.sig_value = res.sg;
	    let cb = formats.certificateBytes(sc, cipherState.params.pv);
	    let skeb = formats.serverKeyExchangeBytes(ske, cipherState.params.pv);
	    let shdb = formats.serverHelloDoneBytes;
	    cipherState.log += cb + skeb + shdb;
	    return [
		handshakeRecord(cipherState.params.pv,cb),
		handshakeRecord(cipherState.params.pv,skeb),
		handshakeRecord(cipherState.params.pv, shdb)
		]
	} else 	throw new Error('only non-auth ecdhe 1.2 implemented.')

    },
    hs_send_server_finished: function (msgs: hs_msg[], cipherState: cipher_state) : record[] {
	var hash1 = getLogHash13(cipherState.log)

	var out_msgs = [];
	let eeb = formats.encryptedExtensionsBytes();
	cipherState.log += eeb;
	out_msgs.push(
	    handshakeRecord(
		cipherState.params.pv,
		eeb
	    )
	);
	var sc = formats.defaultServerCertificate;
	let scb = formats.certificateBytes(sc, cipherState.params.pv);
	cipherState.log += scb;
	out_msgs.push(
	    handshakeRecord(
		cipherState.params.pv, scb
	    )
	);
	var hash2 = getLogHash13(cipherState.log);

	var sCV = tls_core.get_server_certificate_verify_13(cipherState.params.sr,cipherState.params,hash1,sc.chain,hash2);
	var scv = formats.defaultCertificateVerify;
	scv.sig.sig_hash_alg = formats.SS.rsa_pss_sha256;
	scv.sig.sig_value = sCV.sg;
	let scvb = formats.certificateVerifyBytes(scv, cipherState.params.pv);
	cipherState.log += scvb;
	out_msgs.push(
		handshakeRecord(
		    cipherState.params.pv,
		    scvb
		)
	    );

    	var hash3 = getLogHash13(cipherState.log)

	var sSF = tls_core.get_server_finished_13(
	    cipherState.params.sr, hash3
	)

    	var sf = formats.defaultFinished;
        sf.verify_data = sSF.sfin;
	let sfb = formats.finishedBytes(sf);
	cipherState.log += sfb;
    	out_msgs.push(handshakeRecord(cipherState.params.pv, sfb));


	cipherState.write = true;
	cipherState.write_keys = "serverHandshakeKeys";

/*	if (cipherState.keys0) {
	    setServerReadKeys(cipherState.keys0.htk, cipherState);
	    cipherState.params.pv = cipherState.session.pv;
	    cipherState.ae = cipherState.session.ae;
	    cipherState.read = true;
	}
*/
	return out_msgs;
    },
    hs_recv_client_ccs: function (msgs: hs_msg[], cipherState: cipher_state): record[] {
	if (msgs.length === 1 &&
	    msgs[0].ht === formats.HT.client_key_exchange) {
	    var cke = msgs[0].pl;
	    cipherState.log += msgs[0].to_log;

	    if (cipherState.params.kex == 'ECDHE') {
		cipherState.params.gx = cke.ec_public;

	    } else if (cipherState.params.kex == 'DHE') {
		cipherState.params.gx = cke.dh_public;
	    } else if (cipherState.params.kex == 'RSA') {
		throw new Error('only ecdhe/dhe supported');
	    } else {
		throw new Error('only ecdhe/rsa supported');
	    }
	    let res = tls_core.put_client_ccs_no_auth_12(cipherState.params.sr,
							 cipherState.params,
							 getLogHash12(cipherState.log));

	    cipherState.write_keys = "serverDataKeys";
	    cipherState.read_keys = "serverDataKeys";
	    cipherState.read = true;
	    return []
	}
	else throw new Error('CKE expected');
    },

    hs_recv_client_finished0: function (msgs: hs_msg[], cipherState: cipher_state) : record[] {
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

    end_of_early_data_recv: function (cipherState: cipher_state) {
/*	if (cipherState.params.pv === formats.PV.TLS_1p3 &&
	    cipherState.expect_early_data &&
	    cipherState.keys0) {
	    cipherState.expect_early_data = false;
	    setServerReadKeys(cipherState.hs_keys1, cipherState);
	    cipherState.read = true;
	}
*/
    },

    hs_recv_client_finished: function (msgs: hs_msg[], cipherState: cipher_state) : record[] {
	if (cipherState.params.pv === formats.PV.TLS_1p3) {
	    if (msgs.length === 1 &&
		msgs[0].ht === formats.HT.finished){
		var cfin = msgs[0].pl;
		let log1 = getLogHash13(cipherState.log);
		cipherState.log  += msgs[0].to_log;
		let x = tls_core.put_client_finished_no_auth_13(cipherState.params.sr,log1,cfin.verify_data,"");

		cipherState.read = true;
		cipherState.read_keys = "serverDataKeys";
		cipherState.write = true;
		cipherState.write_keys = "serverDataKeys";
		return [];}
	    else throw new Error("expected only client finished")
	} else {
	    if (msgs.length === 1 &&
		msgs[0].ht === formats.HT.finished){
		let log1 = getLogHash12(cipherState.log);
		cipherState.log  += msgs[0].to_log;
		var cfin = msgs[0].pl;
		var rccs = ccsRecord(cipherState.params.pv);
		let res = tls_core.put_client_finished_12(cipherState.params.sr,
							  cipherState.params,
							  log1,
							  cfin.verify_data,
							  "",
							  getLogHash12(cipherState.log));
		var fin = formats.defaultFinished;
		fin.verify_data = res.sfin;
		let finb = formats.finishedBytes(fin);
		var rfin = handshakeRecord(cipherState.params.pv,finb);

		return [rccs, rfin]
	    }
	    else throw new Error("expected only client finished")
	 }
    },
    app_data_recv: function (msg: bytes, cipherState: cipher_state): record[] {
	var out_msgs = [];
	if (cipherState.params.pv == formats.PV.TLS_1p3) {
	    var ticket = {
		lifetime:"00000000",
		ticket: cipherState.params.sr,
	    };
	    let rtickb = formats.sessionTicketBytes(ticket,cipherState.params.pv);
	    cipherState.log += rtickb;
	    var rtick = handshakeRecord(cipherState.params.pv, rtickb);
	    out_msgs.push(rtick);
	}
	var fsd = {
	    type: formats.ContentType.application_data,
	    version: cipherState.params.pv,
	    fragment: (util.a2hex('Hello') + '0d0a0d0a')
	}
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
}


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
