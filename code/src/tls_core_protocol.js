/* @flow */

// TODO: implement/test DHE
// TODO: implement PSK/resumption
// TODO: implement extended master secret
// TODO: RSA-PSS
// TODO: implement AES-256
// TODO: implement RSA encryption? encrypt-then-mac?

// This file contains a core of the TLS 1.3 handshake

var tls_crypto = require('./tls_crypto.js');
var util = require('./util.js');

type client_ephemerals = {
    dh_public: bytes,
    dh_private: bytes
}

type hs_keys = {
    hk: keys,
    ms: bytes,
    cfk: bytes,
    sfk: bytes,
}

type t_keys = {
    tk:keys,
    cats1:bytes,
    sats1:bytes,
    ems:bytes
}

type client_handshake_keys = {
    params: params,
    keys: keys,
    ms: bytes,
    cfk: bytes,
    sfk: bytes,
}

type master_secrets = {
    params: params,
    cert: [bytes],
    cfk: bytes,
    sfk: bytes,
    ms: bytes
}
type data_keys = {
    params: params,
    keys: keys
}

type server_ephemerals = {
    cr:bytes,
    gx:bytes,
    hs:bytes
}

type server_ephemerals_12 = {
    cr:bytes,
    cert: [bytes],
    gy:bytes,
    hs:bytes,
    y:bytes
}

type server_handshake_keys = {
    params: params,
    keys: keys
}

type DB = {
    clientEphemeralSecrets: {[key:string] : client_ephemerals},
    clientHandshakeKeys: {[key:string] : client_handshake_keys},
    clientMasterSecrets: {[key:string] : master_secrets},
    clientDataKeys: {[key:string] : data_keys},
    clientSessions: {[key:string] : sessions},
    serverEphemeralSecrets: {[key:string] : server_ephemerals},
    serverEphemeralSecrets12: {[key:string] : server_ephemerals_12},
    serverHandshakeKeys: {[key:string] : server_handshake_keys},
    serverMasterSecrets: {[key:string] : master_secrets},
    serverDataKeys: {[key:string] : data_keys},
    serverSessions: {[key:bytes] : sessions},
}

var KVS : DB = {
	clientEphemeralSecrets: {},
	clientMasterSecrets: {},
	clientHandshakeKeys: {},
	clientDataKeys: {},
	clientSessions: {},
        serverEphemeralSecrets: {},
        serverEphemeralSecrets12: {},
	serverMasterSecrets: {},
	serverHandshakeKeys: {},
	serverDataKeys: {},
	serverSessions: {},
}

var debug = true

var ProScript = {
    failwith: function(s){throw new Error(s)},
    encoding: tls_crypto.encoding,
    crypto: {
	sha256:    tls_crypto.sha256,
	hmac_sha256:    tls_crypto.hmac_sha256,
	p256_keygen:    tls_crypto.p256r1_keygen,
	p256_public:  tls_crypto.p256r1_public,
	p256_ecdh:        tls_crypto.p256r1_ecdh,
	ff2048_keygen:  tls_crypto.ff2048_keygen,
	ff2048_public:  tls_crypto.ff2048_public,
	ff2048_dh:      tls_crypto.ff2048_public,
	random12Bytes: tls_crypto.random12Bytes,
	random16Bytes: tls_crypto.random16Bytes,
	random32Bytes: tls_crypto.random32Bytes,
	hkdf_extract: tls_crypto.hkdf_extract,
	hkdf_expand_label:  tls_crypto.hkdf_expand_label,
	pkcert:       tls_crypto.cert_get_publicKey,
	sign_rsa_sha256: tls_crypto.rsa_sha256,
	verify_rsa_sha256: tls_crypto.rsa_sha256_verify,
	sign_rsa_pss_sha256: tls_crypto.rsa_pss_sha256,
	verify_rsa_pss_sha256: tls_crypto.rsa_pss_sha256_verify,
	zeroes: util.zeroes,
	server_key: tls_crypto.server_key,
	server_cert: tls_crypto.server_cert,
	tls12_prf_label: tls_crypto.tls12_prf_label,
	deriveKeys_gcm_13: tls_crypto.deriveKeys_gcm_13,
	deriveKeys_gcm_12: tls_crypto.deriveKeys_gcm_12,
	deriveKeys_cbc_12: tls_crypto.deriveKeys_cbc_12,
	deriveKeys_cbc_10: tls_crypto.deriveKeys_cbc_10,
	aes_gcm_encrypt_13: tls_crypto.aes_gcm_encrypt_13,
	aes_gcm_decrypt_13: tls_crypto.aes_gcm_decrypt_13,
	aes_gcm_encrypt_12: tls_crypto.aes_gcm_encrypt_12,
	aes_gcm_decrypt_12: tls_crypto.aes_gcm_decrypt_12,
	aes_cbc_sha_encrypt_12: tls_crypto.aes_cbc_sha_encrypt_12,
	aes_cbc_sha_decrypt_12: tls_crypto.aes_cbc_sha_decrypt_12,
	aes_cbc_sha_encrypt_10: tls_crypto.aes_cbc_sha_encrypt_10,
	aes_cbc_sha_decrypt_10: tls_crypto.aes_cbc_sha_decrypt_10,
	print_debug: function(s){if (debug) console.log(s)}
    },
    state: {
	insert: function(t:string, k:bytes, v) {
	    KVS[t][k] = v;
	},
	get: function(t:string, k:bytes) {
	    return KVS[t][k];
	},
   	remove: function(t:string,k:bytes) {
	    let tab = KVS[t];
	    delete tab[k]
	}
    }
}

let print_debug = ProScript.crypto.print_debug

const sessionKey = {
    k: util.hexStringToByteArray(ProScript.crypto.random16Bytes("k")),
    n: util.hexStringToByteArray(ProScript.crypto.random12Bytes("n"))
};

const defaultKeys = function() : keys {
    return {
	ae: "AES_128_GCM_SHA256",
	  writeMacKey: '',
	  readMacKey: '',
	  writeIv: '',
	  readIv: '',
	  writeKey: '',
	  readKey: '',
	  writeSn: 0,
	  readSn:0
    }
}


const checkClientHelloLog = function(log,cr,gx){ return true;}
const checkServerHelloLog = function(log,params){ return true; }
const checkServerCertificateLog = function(log,params,serverId){ return true; }
const checkServerCertificateVerifyLog = function(log,params,serverId){ return true; }
const checkServerFinishedLog = function(log,params,serverId){ return true; }
const checkClientCertificateLog = function(log,params,serverId,clientId){ return true;}
const checkClientCertificateVerifyLog = function(log,params,serverId,clientId){ return true;}

const checkClientKeyExchangeLog12 = function(log,params,serverId){ return true;}
const checkClientCertificateLog12 = function(log,params,serverId,clientId){ return true;}
const checkServerKeyExchangeParams12 = function(to_sign,gy) { return true; }
const checkServerPreFinishedLog12 = function(log,params,serverId) {return true;}

// we define a series of state passing functions that should translate to the corresponding lines in the pv file

var deriveKeys_13 = ProScript.crypto.deriveKeys_gcm_13

var deriveKeys_12 = function(ae:bytes,ms:bytes,ctx:bytes) {
    switch (ae) {
    case "AES_128_GCM_SHA256":
	return ProScript.crypto.deriveKeys_gcm_12(ms,ctx);
    case "AES_128_CBC_SHA_Stale":
	return ProScript.crypto.deriveKeys_cbc_10(ms,ctx);
    case "AES_128_CBC_SHA_Fresh":
	return ProScript.crypto.deriveKeys_cbc_12(ms,ctx);
    default:
	ProScript.failwith("only AES_128 GCM/CBC supported");
    }
    return defaultKeys()
}

var peerKeys = function(keys:keys): keys {
    return ({
	ae: keys.ae,
	writeMacKey: keys.readMacKey,
	readMacKey: keys.writeMacKey,
	writeKey: keys.readKey,
	readKey: keys.writeKey,
	writeIv: keys.readIv,
	readIv: keys.writeIv,
	writeSn: keys.readSn,
	readSn: keys.writeSn
    });
}



var encrypt_12 = function(keys:keys,plain:bytes,ad:bytes): bytes {
    switch (keys.ae) {
    case "AES_128_GCM_SHA256":
	return ProScript.crypto.aes_gcm_encrypt_12(keys,plain,ad);
    case "AES_128_CBC_SHA_Stale":
	return ProScript.crypto.aes_cbc_sha_encrypt_10(keys,plain,ad);
    case "AES_128_CBC_SHA_Fresh":
	return ProScript.crypto.aes_cbc_sha_encrypt_12(keys,plain,ad);
    default:
	ProScript.failwith("only AES_128 GCM/CBC supported");
	return "";
    }
}

var decrypt_12 = function(keys:keys,cipher:bytes,ad:bytes) {
    switch (keys.ae) {
    case "AES_128_GCM_SHA256":
	return ProScript.crypto.aes_gcm_decrypt_12(keys,cipher,ad);
    case "AES_128_CBC_SHA_Stale":
	return ProScript.crypto.aes_cbc_sha_decrypt_10(keys,cipher,ad);
    case "AES_128_CBC_SHA_Fresh":
	return ProScript.crypto.aes_cbc_sha_decrypt_12(keys,cipher,ad);
    default:
	ProScript.failwith("only AES_128 GCM/CBC supported");
    }
}


/* TLS Client Code */
var dh_keygen = function (gn) : {dh_private:bytes,dh_public:bytes} {
  switch (gn) {
    case "p256":
      var k1 = ProScript.crypto.p256_keygen();
      return {dh_private:k1.ec_private,
	      dh_public:k1.ec_public}
    case "ff2048":
      var k2 = ProScript.crypto.ff2048_keygen();
      return {dh_private:k2.dh_private,
	      dh_public:k2.dh_public}
    default: throw new Error("only p256/ff2048 supported")
  }
}

var gen_dh_keys = function () : dh_keys {
  let keys = {"p256": dh_keygen("p256"),
              "ff2048": dh_keygen("ff2048")};
  return keys;
}

var dh_compute_secret = function(gn,x,gy) {
  switch (gn) {
    case "p256": return ProScript.crypto.p256_ecdh(x, gy);
    case "ff2048": return ProScript.crypto.ff2048_dh(x, gy);
    default: throw new Error("only p256/ff2048 supported")
  }
}
/* Generic Client */
var get_client_hello = function() {
    var cr = ProScript.crypto.random32Bytes('t1');
    let keys = gen_dh_keys();
    return ({cr:cr, keys})
};

/* 1.3 Client */
var set_onertt_hs_keys = function(hs, log): hs_keys {
    let zero_key = ProScript.crypto.zeroes(64);
    var chts = ProScript.crypto.hkdf_expand_label(hs, "c hs traffic", log, 32);
    var shts = ProScript.crypto.hkdf_expand_label(hs, "s hs traffic", log, 32);
    var cfk = ProScript.crypto.hkdf_expand_label(chts, "finished", '', 32);
    var sfk = ProScript.crypto.hkdf_expand_label(shts, "finished", '', 32);
    var hk  = deriveKeys_13(chts, shts);
    var extra = ProScript.crypto.hkdf_expand_label(hs, "derived", ProScript.crypto.sha256(""), 32);
    var ms = ProScript.crypto.hkdf_extract(extra,zero_key);
    return { ms: ms,
	     cfk: cfk,
	     sfk: sfk,
	     hk: hk
	   }
}

var set_onertt_data_keys = function(ms, log) : t_keys {
    var cats = ProScript.crypto.hkdf_expand_label(ms, "c ap traffic", log, 32);
    var sats = ProScript.crypto.hkdf_expand_label(ms, "s ap traffic", log, 32);
    var ems = ProScript.crypto.hkdf_expand_label(ms, "exp master", log, 32);
    var tk = deriveKeys_13(cats, sats);
    var cats1 = ProScript.crypto.hkdf_expand_label(cats, "c ap traffic", log, 32);
    var sats1 = ProScript.crypto.hkdf_expand_label(sats, "s ap traffic", log, 32);

	return {
		tk: tk,
		cats1: cats1,
		sats1: sats1,
		ems: ems
	}
}


var put_server_hello_13 = function(params,psk, x,log) : {hsk:hs_keys, valid:bool} {
    const zero_key = ProScript.crypto.zeroes(64);
    var gyx = dh_compute_secret(params.gn,x,params.gy);
    var es  = ProScript.crypto.hkdf_extract(zero_key,psk);
    var extra = ProScript.crypto.hkdf_expand_label(es, "derived", ProScript.crypto.sha256(""), 32);
    var hs = ProScript.crypto.hkdf_extract(extra,gyx);
    var hsk = set_onertt_hs_keys(hs, log);

    if (checkServerHelloLog(log,params) === true)
	return ({hsk: hsk, valid:true});
    else print_debug ("provided server hello log is inconsistent with context");
    return ({hsk: hsk, valid:false});
}


var put_server_finished_13 = function(params, cert, log1, sv, log2, sfk, vd, log3, ms) : {keys:t_keys, valid:bool} {
    var dk  = set_onertt_data_keys(ms, log3);
    let to_sign = sigval_server_13(log1);
    let pk = ProScript.crypto.pkcert(cert[0]);
    if (ProScript.crypto.verify_rsa_pss_sha256(pk, to_sign, sv) === true)
	if (ProScript.crypto.hmac_sha256(sfk, log2) === vd)
	    if ((checkServerCertificateLog(log1,params,cert) === true) &&
		(checkServerCertificateVerifyLog(log2, params, cert) === true) &&
		(checkServerFinishedLog(log3, params, cert) === true))
		return {keys: dk, valid: true};
    else print_debug ("provided SC/SCV/SF logs are not consistent with context!");
    else print_debug ("server finished invalid!");
    else print_debug ("server certificate verify invalid!");
    return {keys: dk, valid: false};
};

var get_client_finished_no_auth_13 = function(
    params, cert, log3, cfk
) {
    var cfin = ProScript.crypto.hmac_sha256(cfk,log3);
    if (checkServerFinishedLog(log3,params,cert) === true)
	return ({cfin:cfin, valid:true});
    else print_debug("SF log inconsistent with context");
    return ({cfin:cfin, valid:false});
};

var get_client_certificate_verify_13 = function(
    params, cert, certC, log1, sk
) {
    var sg = ProScript.crypto.sign_rsa_pss_sha256(sk, sigval_client_13(log1));
    if ((checkClientCertificateLog(log1,params,cert,certC) === true))
	return ({sg:sg, valid:true});
    else print_debug("CC log inconsistent with context");
    return ({sg:sg, valid:false});
}

var get_client_finished_client_auth_13 = function(
    params, cert, certC, log2, cfk
) {
    var cfin = ProScript.crypto.hmac_sha256(cfk, log2);
    if ((checkClientCertificateVerifyLog(log2, params, cert, certC) === true))
	return ({cfin:cfin, valid:true});
    else print_debug("CCV log inconsistent with context");
    return ({cfin:cfin, valid:false});
}

/* 1.2 Client */

var sigval_12 = function(cr,sr,v) {
    return (cr + sr + v)
}

var put_server_hello_done_no_auth_12 = function(params,x,cert,dhp,sv,log) {
    let pk = ProScript.crypto.pkcert(cert[0]);
    let pms = dh_compute_secret(params.gn,x, params.gy);
    let ms = ProScript.crypto.tls12_prf_label(pms,
					      'master secret',
					      (params.ext_ms? log: params.cr + params.sr),
					      48
					     );

    let cvd = ProScript.crypto.tls12_prf_label(ms,
					       'client finished',
					       log,
					       12);
    let dk = deriveKeys_12(params.ae,ms,params.sr + params.cr);

    let to_sign = sigval_12(params.cr,params.sr,dhp);
    if (ProScript.crypto.verify_rsa_sha256(pk, to_sign, sv) === true)
	if ((checkClientKeyExchangeLog12(log,params,cert) === true) &&
	    (checkServerKeyExchangeParams12(dhp,params.gy) === true))
	    return ({dk: dk, ms:ms, cfin:cvd, valid:true});
    else print_debug ("provided SKE/CKE log is inconsistent with context");
    else print_debug ("server signature did not verify");
    return ({dk:dk, ms: ms, cfin:cvd, valid:false});
}

var put_server_finished_no_auth_12 = function(params,cert,log,sfin,ms) {
    let svd = ProScript.crypto.tls12_prf_label(ms,
					       'server finished',
					       log,
					       12);
    if (svd === sfin)
	if (checkServerPreFinishedLog12(log,params,cert) === true)
	    return true
    else print_debug ("provided SF log is inconsistent with context");
    else print_debug ("server finished did not verify");
    return false;
}


/* TLS Server Code */

/* 1.3 Server */

var put_client_hello_13 = function(cr, psk, gn, gx, log) {
    let zero_key = ProScript.crypto.zeroes(64);
    const sr = ProScript.crypto.random32Bytes('t3');
    const k  = dh_keygen(gn);
    const gy = k.dh_public;
    var gxy = dh_compute_secret(gn,k.dh_private,gx);
    var es  = ProScript.crypto.hkdf_extract(zero_key,psk);
    var extra = ProScript.crypto.hkdf_expand_label(es, "derived", ProScript.crypto.sha256(""), 32);
    var hs = ProScript.crypto.hkdf_extract(extra,gxy);
    if (checkClientHelloLog(log,cr,gx) === true)
	return ({sr:sr, gy:gy, hs:hs, valid:true});
    else print_debug("CH log inconsistent with context");
    return ({sr:sr, gy:gy, hs:hs, valid:false});
}


var get_server_certificate_verify_13 = function(params, log1, hs, cert, log2, sk) {
    let hs_keys = set_onertt_hs_keys(hs,log1);
    var sg = ProScript.crypto.sign_rsa_pss_sha256(sk, sigval_server_13(log2));
    if ((checkServerHelloLog(log1, params) === true) &&
	(checkServerCertificateLog(log2, params, cert) === true))
	return ({hsk:hs_keys,sg:sg, valid:true});
    else  print_debug("SH/SC log inconsistent with context");
    return ({hsk:hs_keys,sg:sg, valid:false});
}

var get_server_finished_13 = function(params,cert,log,sfk) {
    var sfin = ProScript.crypto.hmac_sha256(sfk,log);

    if (checkServerCertificateVerifyLog(log, params, cert) === true)
	return {sfin: sfin, valid:true};
    else print_debug("CV log inconsistent with context");
    return {sfin: sfin, valid:false};
}

var sigval_server_13 = function(hash) {
    var sigval = (
	'20202020202020202020202020202020202020' +
	    '20202020202020202020202020202020202020' +
	    '20202020202020202020202020202020202020' +
	    '20202020202020' + util.a2hex(
		'TLS 1.3, server CertificateVerify'
	    ) + '00' + hash);

	return sigval;
}

var sigval_client_13 = function(hash) {
    var sigval = (
	'20202020202020202020202020202020202020' +
	    '20202020202020202020202020202020202020' +
	    '20202020202020202020202020202020202020' +
	    '20202020202020' + util.a2hex(
		'TLS 1.3, client CertificateVerify'
	    ) + '00' + hash);
    return sigval
}

var put_client_finished_no_auth_13 = function(
    params, cert, log, cfk, cfin
) {
    if (ProScript.crypto.hmac_sha256(cfk, log) === cfin) {
	if (checkServerFinishedLog(log,params,cert) === true)
	    return true;
	else {
	    print_debug("SFIN log inconsistent with context");
	    return false
	}}
    else
	return false;
}

var put_client_finished_client_auth_13 = function(
    params, cert, certC, log1, cv, log2, cfk, cfin
) {
    let pkC = ProScript.crypto.pkcert(certC);
    if ((ProScript.crypto.verify_rsa_pss_sha256(pkC, sigval_client_13(log1), cv) === true) &&
	(ProScript.crypto.hmac_sha256(cfk, log2) === cfin))
	if ((checkClientCertificateLog(log1, params, cert, certC) === true) &&
	    (checkClientCertificateVerifyLog(log2, params, cert, certC) === true))
	    return true;
	else {
	    print_debug("CC/CCV logs inconsistent with context");
	    return false
	}
    else
    return false;
}

const set_rms_ems = function (ms, log) {
	const rms = ProScript.crypto.hkdf_expand_label(ms, "resumption master secret", log, 32);
	const ems = ProScript.crypto.hkdf_expand_label(ms, "exporter master secret", log, 32);
	return ({
		rms: rms,
		ems: ems
	});
}

/* 1.2 Server */

var put_client_hello_12 = function(cr,gn) {
    const sr = ProScript.crypto.random32Bytes('t3');
    const k = dh_keygen(gn);
    const y  = k.dh_private;
    const gy = k.dh_public;
    return ({sr:sr, gy:gy, y:y, valid:true});
}

var get_server_hello_done_12 = function(cr,sr,gy,dhp,sk){
    let to_sign = sigval_12(cr,sr,dhp);
    let sg = ProScript.crypto.sign_rsa_sha256(sk,to_sign);
    if (checkServerKeyExchangeParams12(dhp,gy) === true)
	return {sg:sg, valid:true}
    else print_debug("provided SKE is not consistent with params");
    return {sg:sg, valid:false}
}

var put_client_ccs_no_auth_12 = function(params,y,cert,log1) {
    let pms = dh_compute_secret(params.gn, y, params.gx);
    let ms = ProScript.crypto.tls12_prf_label(pms,
					      'master secret',
					      (params.ext_ms? log1: params.cr + params.sr),
					      48
					     );
    let dk = deriveKeys_12(params.ae,ms,params.sr + params.cr);

    return ({dk: dk, ms:ms, valid:true});
}

var put_client_finished_12 = function(params,cert,ms,log1,cfin,log2){
    let cvd = ProScript.crypto.tls12_prf_label(ms,
					       'client finished',
					       log1,
					       12);
    let svd = ProScript.crypto.tls12_prf_label(ms,
					       'server finished',
					       log2,
					       12);
    if (cvd === cfin)
	if ((checkClientKeyExchangeLog12(log1,params,cert) === true) &&
	    (checkServerPreFinishedLog12(log2,params,cert) === true))
	    return ({cfin:cvd, sfin:svd, valid:true});
    else print_debug ("provided CKE/SF log is inconsistent with context");
    else print_debug ("client finished did not verify");
    return ({cfin:cvd, sfin:svd, valid:false});
}


module.exports = {
	get_client_hello: function() {
		var sCH = get_client_hello();
		ProScript.state.insert(
		    'clientEphemeralSecrets',sCH.cr,
		    sCH.keys
		);
	    return {
		cr: sCH.cr,
		public_values: {p256:sCH.keys.p256.dh_public,
				ff2048:sCH.keys.ff2048.dh_public}
	    };
	},
    put_server_hello_13: function(cr:bytes, params:params, ticket:bytes, log:bytes) {
	var sec = ProScript.state.get(
	    'clientEphemeralSecrets',
	    cr
	);
        let psk = ProScript.crypto.zeroes(64);
        let psk_context = ProScript.crypto.zeroes(64);
	let s = ProScript.state.get("clientSessions",ticket);
	if (s) {
	    psk = ProScript.crypto.hkdf_expand_label(s.rms, "resumption psk", "", 32);
	    psk_context = ProScript.crypto.hkdf_expand_label(s.rms, "resumption context", "", 32);
	}

	var rSH = put_server_hello_13(params, psk,
				      sec[params.gn].dh_private, log);
	ProScript.state.remove('clientEphemeralSecrets', cr);
	if (rSH.valid) {
	    ProScript.state.insert(
		'clientHandshakeKeys',
		cr, {params:params,
		     keys:rSH.hsk.hk,
		     ms:rSH.hsk.ms,
		     cfk:rSH.hsk.cfk,
		     sfk:rSH.hsk.sfk}
	    );
	}
    	return {psk_ctx: psk_context, valid:rSH.valid};

    },

    put_server_finished_13: function(cr:bytes,
				     cert: [bytes],
				     log1:bytes,
				     sv:bytes,
				     log2:bytes,
				     sfin:bytes,
				     log3:bytes) {
	var hs_keys = ProScript.state.get(
	    'clientHandshakeKeys',
	    cr);

	var rSF = put_server_finished_13(hs_keys.params,cert,log1,sv,log2,hs_keys.sfk,sfin,log3,hs_keys.ms);
	ProScript.state.insert('clientMasterSecrets', cr,
			       {params:hs_keys.params,
				cert:cert,
				cfk:hs_keys.cfk,
				sfk:hs_keys.sfk,
				ms:hs_keys.ms});
	ProScript.state.insert(
	    'clientDataKeys',
	    cr, {params:hs_keys.params, keys:rSF.keys.tk}
	);
	return;
    },

    get_client_finished_no_auth_13: function(cr:bytes,log:bytes) {
	var ms_sec = ProScript.state.get(
	    'clientMasterSecrets',
	    cr
	);
	var rCF = get_client_finished_no_auth_13(ms_sec.params,ms_sec.cert,log,ms_sec.cfk);
	return rCF
    },

    put_session_ticket_13: function(cr:bytes,log:bytes,tick:bytes) {
	var ms_sec = ProScript.state.get(
	    'clientMasterSecrets',
	    cr
	);
  	var sSF = set_rms_ems(ms_sec.ms, log);
	ProScript.state.insert('clientSessions',tick,{params:ms_sec.params,cert:ms_sec.cert,ticket:tick,rms:sSF.rms,ems:sSF.ems});
	ProScript.state.remove('clientMasterSecrets',cr);
	return;
    },


    put_client_hello_13: function(cr:bytes, gx:bytes, ticket:bytes, log:bytes) {
	let s = ProScript.state.get("serverSessions",ticket);
        let psk = ProScript.crypto.zeroes(64);
        let psk_context = ProScript.crypto.zeroes(64);
	if (s) {
	    psk = ProScript.crypto.hkdf_expand_label(s.rms, "resumption psk", "", 32);
	    psk_context = ProScript.crypto.hkdf_expand_label(s.rms, "resumption context", "", 32);
	}
	var rCH = put_client_hello_13(cr, psk, "p256", gx, log);
	let sr = rCH.sr;
	let gy = rCH.gy;
	ProScript.state.insert(
	    'serverEphemeralSecrets',
	    sr,
	    {cr:cr,gx:gx,hs:rCH.hs}
	);
	return {
	    sr: sr,
	    gy: gy,
	    psk_ctx: psk_context
	}
    },

    get_server_certificate_verify_13: function(sr:bytes,
					       params:params,
					       log1:bytes,
					       cert: bytes[],
					       log2:bytes) {
	let hs_sec = 	ProScript.state.get(
	    'serverEphemeralSecrets',sr);
  	var res = get_server_certificate_verify_13(params,log1,hs_sec.hs, cert, log2, ProScript.crypto.server_key);


	if (res.valid && params.cr === hs_sec.cr && params.gx === hs_sec.gx) {
	    ProScript.state.remove('serverEphemeralSecrets',sr);
	    ProScript.state.insert(
		'serverHandshakeKeys',
		sr, {params:params, keys: peerKeys(res.hsk.hk)}
	    );
	    ProScript.state.insert(
		'serverMasterSecrets',
		sr, {params:params,cert:cert,ms:res.hsk.ms,cfk:res.hsk.cfk,sfk:res.hsk.sfk}
	    );
	    return {sg:res.sg, valid:res.valid}
	}
	else return {sg:res.sg, valid:res.valid}
    },

    get_server_finished_13: function(sr:bytes, log:bytes) {
	var ms_sec = ProScript.state.get(
	    'serverMasterSecrets',
	    sr
	);
  	var sSF = get_server_finished_13(ms_sec.params,ms_sec.cert,log,ms_sec.sfk);
	return sSF;
    },

    put_client_finished_no_auth_13: function(sr:bytes,
					     log:bytes,
					     cfin:bytes,
					     ticket:bytes) {
	var ms_sec = ProScript.state.get(
	    'serverMasterSecrets',
	    sr
	);
	let dk = set_onertt_data_keys(ms_sec.ms,log);
	ProScript.state.insert(
	    'serverDataKeys',
	    sr, {params:ms_sec.params,keys:peerKeys(dk.tk)}
	);
	if (put_client_finished_no_auth_13(ms_sec.params,
					ms_sec.cert,
					log,
					ms_sec.cfk,
					cfin)) {
  	    var sSF = set_rms_ems(ms_sec.ms, log);
	    ProScript.state.remove('serverMasterSecrets',sr);
	    ProScript.state.insert('serverSessions',
				   ticket,
				   {params:ms_sec.params,
				    cert:ms_sec.cert,
				    ticket:ticket,
				    rms:sSF.rms,
				    ems:sSF.ems})
	}
	return {valid: true};
    },

    put_server_hello_done_no_auth_12: function(cr:bytes,
					       params:params,
					       cert: [bytes],
					       dhp:bytes,
					       sv:bytes,
					       log:bytes) {
	var sec = ProScript.state.get(
	    'clientEphemeralSecrets',
	    cr
	);
	var rSH = put_server_hello_done_no_auth_12(params, sec[params.gn].dh_private, cert, dhp, sv, log);
	ProScript.state.remove('clientEphemeralSecrets', cr);
//	console.log("TABLE UPDATE");
	//console.log(rSH);
	if (rSH.valid || debug) {
	    ProScript.state.insert(
		'clientDataKeys',
		cr, {params:params,keys:rSH.dk}
	    );
	    //	console.log(KVS);
	    ProScript.state.insert(
		'clientMasterSecrets',
		cr, {params:params,
		     cert:cert,
		     cfk: rSH.ms,
		     sfk: rSH.ms,
		     ms: rSH.ms}
	    );
	}
    	return {cfin:rSH.cfin,ms:rSH.ms,dk:rSH.dk};
    },

    put_server_finished_no_auth_12 : function(cr:bytes,
					      tick:bytes,
					      log:bytes,
					      sfin:bytes) {
	let ms_sec = ProScript.state.get(
	    'clientMasterSecrets',
	    cr);
	let res = put_server_finished_no_auth_12(ms_sec.params,ms_sec.cert,log,sfin,ms_sec.ms);
	if (res === true && tick !== '')
	    ProScript.state.insert('clientSessions',
				   tick,
				   {params:ms_sec.params,
				    cert:ms_sec.cert,
				    ticket:tick,
				    rms:ms_sec.ms,
				    ems:ms_sec.ms});

	return res;
    },

    put_client_hello_12: function (cr:bytes,cert: [bytes]) {
	let rCH = put_client_hello_12(cr,"p256");
	ProScript.state.insert('serverEphemeralSecrets12',
			       rCH.sr,
			       {cr:cr,
				cert:cert,
				gy:rCH.gy,
				y:rCH.y});
	return ({sr:rCH.sr,gy:rCH.gy})
    },

    get_server_hello_done_12: function (sr:bytes,dhp:bytes) {
	let s_sec = ProScript.state.get('serverEphemeralSecrets12',
					sr);
	let sk = ProScript.crypto.server_key;
	let sg = get_server_hello_done_12(s_sec.cr,sr,s_sec.gy,dhp,sk);
	return sg;
    },

    put_client_ccs_no_auth_12: function(sr:bytes,
					params:params,
				       	log1:bytes) {

	let s_sec = ProScript.state.get('serverEphemeralSecrets12',
					sr);
	let ks = put_client_ccs_no_auth_12(params,s_sec.y,s_sec.cert,log1);
	if (ks.valid) {
	    ProScript.state.insert(
		'serverDataKeys',
		sr, {params:params,keys:peerKeys(ks.dk)}
	    );
	    ProScript.state.insert(
		'serverMasterSecrets',
		sr, {params:params,cert:s_sec.cert,
		     ms:ks.ms,cfk:ks.ms,sfk:ks.ms}
	    );
	    return ({valid:true})
	}
	return {valid:false}
    },

    put_client_finished_12: function(sr:bytes,
				     params:params,
				     log1:bytes,
				     cfin:bytes,
				     ticket:bytes,
				     log2:bytes) {
	var ms_sec = ProScript.state.get(
	    'serverMasterSecrets',
	    sr
	);

	let ks = put_client_finished_12(params,ms_sec.cert,ms_sec.ms,log1,cfin,log2);
	if (ks.valid) {
	    ProScript.state.insert('serverSessions',
				   ticket,
				   {params:ms_sec.params,
				    cert:ms_sec.cert,
				    ticket:ticket,
				    rms:ms_sec.ms,
				    ems:ms_sec.ms});
	    return {sfin:ks.sfin,valid:true}
	}
	return {sfin:ks.sfin,valid:false}
    },

    encrypt_13: function (index:bytes,
			  table:string,
			  plain:bytes,
			  ct:bytes) {
	print_debug("encrypting with "+table+" for "+index);
	var keys = ProScript.state.get(table,index).keys;
	print_debug("got keys!");
	print_debug(keys);
	return ProScript.crypto.aes_gcm_encrypt_13(keys,plain,ct)
    },

    decrypt_13: function (index:bytes,
			  table:string,
			  cipher:bytes) {
	print_debug("decrypting with "+table+" for "+index);
	var keys = ProScript.state.get(table,index).keys;
	print_debug("got keys!");
	print_debug(keys);
	return ProScript.crypto.aes_gcm_decrypt_13(keys,cipher)
    },


    encrypt_12: function (index:bytes,
			  table:string,
			  plain:bytes,
			  ad:bytes) {
	print_debug("encrypting with "+table+" for "+index);
	//	console.log(KVS);
	var keys = ProScript.state.get(table,index).keys;
	print_debug("got keys!");
	print_debug(keys);
	return encrypt_12(keys,plain,ad)
    },

    decrypt_12: function (index:bytes,
			  table:string,
			  cipher:bytes,
			  ad:bytes) {
	print_debug("decrypting with "+table+" for "+index);
	var keys = ProScript.state.get(table,index).keys;
	print_debug("got keys!");
	print_debug(keys);
	return decrypt_12(keys,cipher,ad)
    },
    defaultKeys: defaultKeys,
    sessionKey: sessionKey,
    getClientSession: function (ticket:string) {
	let s = ProScript.state.get("clientSessions",ticket);
	if (s) return {params:s.params, cert:s.cert, ticket:s.ticket}
	else return undefined
    },
    getServerSession: function (ticket:string) {
	let s = ProScript.state.get("serverSessions",ticket);
	if (s) return {params:s.params, cert:s.cert, ticket:s.ticket}
	else return undefined
    }
};
