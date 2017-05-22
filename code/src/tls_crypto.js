/* @flow weak */
/* Begin: tls-crypto.js: TLS-specific crypto constructs and wrappers for PSCL */

'use strict';
var debug = false;
var crypto = require('crypto');
var rsasign = require('jsrsasign');
var fs = require('fs');
var util = require('./util.js');

const nonce = function (n:number) : bytes {
    const buf = crypto.randomBytes(n);
    return buf.toString('hex');
}

const aes_gcm_encrypt = function (k:bytes, n:bytes, p:bytes, ad:bytes) {
    var kb = new Buffer(k, 'hex');
    var ivb = new Buffer(n, 'hex');
    var pb = new Buffer(p, 'hex');
    var adb = new Buffer(ad, 'hex');
    var c = crypto.createCipheriv('aes-128-gcm', kb, ivb);
    c.setAAD(adb);
    c.setAutoPadding(false);
    var res = c.update(pb).toString('hex');
    res += c.final().toString('hex');
    res += c.getAuthTag().toString('hex');
    return res;
}

const aes_gcm_decrypt = function (k:bytes, n:bytes, c:bytes, ad:bytes) : {plaintext:bytes, auth_ok:boolean} {
    var sp = util.split(c, util.getLength(c) - 16);
    var kb = new Buffer(k, 'hex');
    var ivb = new Buffer(n,'hex');
    var cb = new Buffer(sp.fst, 'hex');
    var atb = new Buffer(sp.snd, 'hex');
    var adb = new Buffer(ad, 'hex');
    var dc = crypto.createDecipheriv('aes-128-gcm', kb, ivb);
    dc.setAAD(adb);
    dc.setAuthTag(atb);
    dc.setAutoPadding(false);
    var res = dc.update(cb).toString('hex');
    try {
	res += dc.final().toString('hex');
	return ({
	    plaintext: res,
	    auth_ok: true
	})
    } catch (e) {
	return ({
	    plaintext: res,
	    auth_ok: false
	})
    }
}
const randomBytes = function (n:number) {
    return (crypto.randomBytes(n)).toString('hex');
};
const random12Bytes = function (a:string) {
    return randomBytes(12);
};
const random16Bytes = function (a:string) {
    return randomBytes(16);
};
const random32Bytes = function (a:string) {
    return randomBytes(32);
};
const aes_cbc_encrypt = function (k, iv, p) {
    var kb = new Buffer(k, 'hex');
    var pb = new Buffer(p, 'hex');
    var ivb = new Buffer(iv);
    var c = crypto.createCipheriv('aes-128-cbc', kb, ivb);
    c.setAutoPadding(false);
    var res = c.update(pb).toString('hex');
    res += c.final().toString('hex');
    return res;
}
const aes_cbc_decrypt = function (k, iv, c) {
    var cb = new Buffer(c, 'hex');
    var kb = new Buffer(k, 'hex');
    var ivb = new Buffer(iv, 'hex');
    var c = crypto.createDecipheriv('aes-128-cbc', kb, ivb);
    c.setAutoPadding(false);
    var res = c.update(cb).toString('hex');
    res += c.final().toString('hex');
    return res;
}



const hmac_sha256 = function (secret, data) {
    var kb = new Buffer(secret, 'hex');
    var db = new Buffer(data, 'hex');
    var m = crypto.createHmac('sha256', kb);
    m.update(db);
    return m.digest('hex');
}
const hmac_sha1 = function (secret, data) {
    var kb = new Buffer(secret, 'hex');
    var db = new Buffer(data, 'hex');
    var m = crypto.createHmac('sha1', kb);
    m.update(db);
    return m.digest('hex');
}
const hmac_md5 = function (secret, data) {
    var kb = new Buffer(secret, 'hex');
    var db = new Buffer(data, 'hex');
    var m = crypto.createHmac('md5', kb);
    m.update(db);
    return m.digest('hex');
};
const sha256 = function (data:bytes) {
    var db = new Buffer(data, 'hex');
    return crypto.createHash('sha256').update(db).digest('hex');
}
    const sha256_rsa = function (data:bytes) {
    var db = new Buffer(data, 'utf8');
    return crypto.createHash('sha256').update(db).digest('utf8');
}
	const sha1 = function (data:bytes) {
    var db = new Buffer(data, 'hex');
    return crypto.createHash('sha1').update(db).digest('hex');
}
	    const md5 = function (data:bytes) {
    var db = new Buffer(data, 'hex');
    return crypto.createHash('md5').update(db).digest('hex');
}
const p256r1_keygen = function () {
    var ecdh = crypto.createECDH('prime256v1');
    var priv = (crypto.randomBytes(32)).toString('hex');
    ecdh.setPrivateKey(priv, 'hex');
    return ({
	ec_private: ecdh.getPrivateKey('hex'),
	ec_public: ecdh.getPublicKey('hex')
    })
}
const p256r1_getX = function (pub) {
    return pub.slice(2, 66);
}
const p256r1_ecdh = function (priv, pub) {
    var ecdh = crypto.createECDH('prime256v1');
    ecdh.setPrivateKey(priv, 'hex');
    return ecdh.computeSecret(pub, 'hex').toString('hex');
}
const p256r1_public = function (priv) {
    var ecdh = crypto.createECDH('prime256v1');
    ecdh.setPrivateKey(priv, 'hex');
    return ecdh.getPublicKey('hex').toString('hex');
}

const ff2048_prime = "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd65612433f51f5f066ed0856365553\
ded1af3b557135e7f57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae56ede76372bb190b07a7c8ee0a6\
d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff"

const ff2048_keygen = function() {
	var dh = crypto.createDiffieHellman(ff2048_prime,'hex');
	dh.generateKeys();
	return {
				dh_private: dh.getPrivateKey('hex'),
				dh_public: dh.getPublicKey('hex')
	};
}

const ff2048_public = function (priv) {
		var dh = crypto.createDiffieHellman(ff2048_prime,'hex');
		dh.setPrivateKey(priv, 'hex');
		return dh.getPublicKey('hex').toString('hex');
};

const ff2048_dh = function (priv, pub) {
			var dh = crypto.createDiffieHellman(ff2048_prime,'hex');
			dh.setPrivateKey(priv, 'hex');
			return dh.computeSecret(pub, 'hex').toString('hex');
};

const rsa_md5 = function (k, m) {
    var mb = new Buffer(m, 'hex');
    var s = crypto.createSign('RSA-MD5');
    s.update(mb);
    return s.sign(k, 'hex');
}
const rsa_sha1 = function (k, m) {
    var mb = new Buffer(m, 'hex');
    var s = crypto.createSign('RSA-SHA1');
    s.update(mb);
    return s.sign(k, 'hex');
}
const rsa_sha256 = function (k, m) {
    var mb = new Buffer(m, 'hex');
    var s = crypto.createSign('RSA-SHA256');
    s.update(mb);
    return s.sign(k, 'hex');
}
const rsa_sha256_verify = function (k, m, s) {
    console.log("key:"+k);
    console.log("msg:"+m);
    console.log("sig:"+s);
    var mb = new Buffer(m, 'hex');
    var sb = new Buffer(s, 'hex');
    var s = crypto.createVerify('RSA-SHA256');
    s.update(mb);
    return s.verify(k, sb, 'hex');
}


const rsa_pss_sha256 = function (k, m) {
    //return rsa_sha256(k,m);
    /* Doesn't work on Node 7.1, only on nightly */
    var sk = {
	key: k,
	padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
	saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
    };
    var mb = new Buffer(m, 'hex');
    var s = crypto.createSign('RSA-SHA256');
    s.update(mb);
    return s.sign(sk, 'hex');
}
const rsa_pss_sha256_verify = function (k, m, s) {
    //    return rsa_sha256_verify(k,m,s);

    /* Doesn't work on Node 7.1, only on nightly */
    
    console.log("key:"+k);
    console.log("msg:"+m);
    console.log("sig:"+s);
    var pk = {
	key: k,
	padding: crypto.constants.RSA_PKCS1_PSS_PADDING
    };
    var mb = new Buffer(m, 'hex');
    var sb = new Buffer(s, 'hex');
    var s = crypto.createVerify('RSA-SHA256');
    s.update(mb);
    return s.verify(pk, sb, 'hex');
    
}

const rsa_sign = function (k, m) {
    var mb = new Buffer(m, 'hex');
    var sk = {
	key: k,
	padding: crypto.constants.RSA_PKCS1_PADDING
    };
    var s = crypto.privateEncrypt(sk, mb);
    return s.toString('hex');
}
const rsa_encrypt = function (pk, m) {
    var mb = new Buffer(m, 'hex');
    var k = {
	key: pk,
	padding: crypto.constants.RSA_PKCS1_PADDING
    };
    var s = crypto.publicEncrypt(k, mb);
    return s.toString('hex');
}
const rsa_decrypt = function (sk, m) {
    var mb = new Buffer(m, 'hex');
    var k = {
	key: sk,
	padding: crypto.constants.RSA_PKCS1_PADDING
    };
    var s = crypto.privateDecrypt(k, mb);
    return s.toString('hex');
}
const p_hash = function (hf, secret, label, data, len) {
    const seed = label + data;
    var prev = seed;
    var out = "";
    while (util.getLength(out) < len) {
	prev = hf(secret, prev);
	out += hf(secret, prev + seed);
    }
    if (util.getLength(out) > len) out = util.split(out, len).fst;
    return out
}
const xor = function (s1:string, s2:string, l:number) {
    let b1 = util.hexStringToByteArray(s1);
    let b2 = util.hexStringToByteArray(s2);
    let res = [];
    for (var i = 0; i < l; i++)
	res.push(b1[i] ^ b2[i]);
    return util.byteArrayToHexString(res);
}

const tls10_prf = function (secret, label, data, len) {
    var l = util.getLength(secret);
    var h = (l % 2 == 0 ? l / 2 : (l + 1) / 2);
    var sp = util.split(secret, h);
    var hmd5 = p_hash(hmac_md5, sp.fst, label, data, len);
    var hsha1 = p_hash(hmac_sha1, sp.snd, label, data, len);
    return xor(hmd5, hsha1, len);
}
const tls12_prf = function (secret, label, data, len) {
    return p_hash(hmac_sha256, secret, label, data, len);
}

const tls12_prf_label = function (secret, label, data, len) {
    return p_hash(hmac_sha256, secret, util.a2hex(label), data, len);
}

const hkdf_extract = function (salt, secret) {
    const res = hmac_sha256(salt, secret);
    console.log("EXTRACT salt:" + salt + "\nsecret:" + secret + "\nresult(a):" + res);
    return res;
}


    function vlbytes(n:number, data:string) : string {
		//        console.log("data.length="+data.length+",d="+data);
		const l = util.getLength(data);
		const lb = util.bytes_of_int(l, n);
		return lb + data
	}

const hkdf_expand_label = function (secret, label, hashvalue, len:number) {
    var count = 0;
    var currlen = 0;
    var prev = "";
    var t = "";
    var info = util.bytes_of_int(len, 2) + vlbytes(1, util.a2hex("tls13 " + label)) + vlbytes(1, hashvalue);
    while (currlen < len) {
	count++;
	prev = hmac_sha256(secret, prev + info + util.bytes_of_int(count, 1));
	t = t + prev;
	currlen = currlen + 32;
    }
    const res = util.substr(t, 0, 2 * len); //Should this be 2* or is substr well-defined for bytes?
    console.log(
	"EXPAND secret:" + secret +
	    "\nlabel:" + label +
	    "\nhash:" + hashvalue +
	    "\ninfo:" + info +
	    "\nresult(b):" + res
    );
    return res
}


var deriveKeys_gcm_12 = function (ms:bytes,ctx:bytes):keys {
    let kb = tls12_prf_label(ms,
					      'key expansion',
					      ctx,
					      40);
    let sp1 = util.split(kb, 16);
    let sp2 = util.split(sp1.snd, 16);
    let sp3 = util.split(sp2.snd, 4);
    return ({
	ae: "AES_128_GCM_SHA256",
	writeMacKey: '',
	readMacKey: '',
	writeKey: sp1.fst,
	readKey: sp2.fst,
	writeIv: sp3.fst,
	readIv: sp3.snd,
	writeSn: 0,
	readSn: 0
    })
}


var deriveKeys_cbc_10 = function (ms:bytes,ctx:bytes):keys {
    let kb = tls12_prf_label(ms,
					      'key expansion',
					      ctx,
					      104);
    let sp1 = util.split(kb, 20);
    let sp2 = util.split(sp1.snd, 20);
    let sp3 = util.split(sp2.snd, 16);
    let sp4 = util.split(sp3.snd, 16);
    let sp5 = util.split(sp4.snd, 16);
    return ({
	ae: "AES_128_CBC_SHA_Stale",
	writeMacKey: sp1.fst,
	readMacKey: sp2.fst,
	writeKey: sp3.fst,
	readKey: sp4.fst,
	writeIv: sp5.fst,
	readIv: sp5.snd,
	writeSn: 0,
	readSn: 0
    })
}

var deriveKeys_cbc_12 = function (ms:bytes,ctx:bytes):keys {
    let kb = tls12_prf_label(ms,
					      'key expansion',
					      ctx,
					      72);
    let sp1 = util.split(kb, 20);
    let sp2 = util.split(sp1.snd, 20);
    let sp3 = util.split(sp2.snd, 16);
    return ({
	ae: "AES_128_CBC_SHA_Fresh",
	writeMacKey: sp1.fst,
	readMacKey: sp2.fst,
	writeKey: sp3.fst,
	readKey: sp3.snd,
	writeIv: '',
	readIv: '',
	writeSn: 0,
	readSn: 0
    })
}

var deriveKeys_gcm_13 = function (ck:bytes, sk:bytes):keys {
    return ({
	ae: "AES_128_GCM_SHA256_TLS13",
	writeMacKey: '',
	readMacKey: '',
	writeKey: hkdf_expand_label(ck, "key", "", 16),
	readKey: hkdf_expand_label(sk, "key", "", 16),
	writeIv:  hkdf_expand_label(ck, "iv", "", 12),
	readIv:  hkdf_expand_label(sk, "iv", "", 12),
	writeSn: 0,
	readSn: 0
	})
}

var aes_gcm_encrypt_13 = function(keys:keys,plain:bytes,ct:bytes) {
    let sn12 = util.bytes_of_int(keys.writeSn,12);
    let nonce = xor(sn12,keys.writeIv,12);
    let cipher = aes_gcm_encrypt(keys.writeKey,nonce,plain+ct,"");
    keys.writeSn = keys.writeSn + 1;
    return cipher
}

var aes_gcm_decrypt_13 = function(keys:keys,cipher:bytes) {
    let sn12 = util.bytes_of_int(keys.readSn,12);
    let nonce = xor(sn12,keys.readIv,12);
    let frag = aes_gcm_decrypt(keys.readKey,nonce,cipher,"");
    let sp = util.split(frag.plaintext, util.getLength(frag.plaintext) - 1);
    keys.readSn = keys.readSn + 1;
    if (frag.auth_ok === true)
	return {valid: true, plaintext: sp.fst, ct: sp.snd}
    else
	return {valid: false, plaintext: sp.fst, ct: sp.snd}
}

var aes_gcm_encrypt_12 = function(keys,plain,ad) {
    let n8 = randomBytes(8);
    let nonce = keys.writeIv + n8;
    let snb = util.bytes_of_int(keys.writeSn,8);
    let lenb = util.bytes_of_int(util.getLength(plain),2);
    let cipher = n8 + aes_gcm_encrypt(keys.writeKey,
					    nonce,
					    plain,
					    snb+ad+lenb);
    keys.writeSn = keys.writeSn + 1;
    return cipher
}

var aes_gcm_decrypt_12 = function(keys,cipher,ad) {
    let sp = util.split(cipher,8);
    let n8 = sp.fst;
    cipher = sp.snd;
    let nonce = keys.readIv + n8;
    let snb = util.bytes_of_int(keys.readSn,8);
    let lenb = util.bytes_of_int(util.getLength(cipher) - 16,2);
    let adb = snb + ad + lenb;
    let frag = aes_gcm_decrypt(keys.readKey,
					    nonce,
					    cipher,
					    adb);
    keys.readSn = keys.readSn + 1;
    if (frag.auth_ok === true)
	return {valid: true, plaintext: frag.plaintext}
    else
	return {valid: false, plaintext: frag.plaintext}
}

const cbc_pad = function (b,block) {
    let l = util.getLength(b) + 1;
    let pl = block - (l % block);
    var v = "";
    var i = 0;
    for (i = 0; i <= pl; i++) {
	v += util.bytes_of_int(l % 256, 1);
    }
    return (b+v);
}

const cbc_last_block = function (e,block) {
    let sp = util.split(e, util.getLength(e) - block);
    return sp.snd
}

var aes_cbc_sha_encrypt_10 = function(keys,plain,ad) {
    let snb = util.bytes_of_int(keys.writeSn,8);
    let lenb = util.bytes_of_int(util.getLength(plain),2);
    let adb = snb + ad + lenb;
    let m = hmac_sha1(keys.writeMacKey, adb + plain);
    let p = cbc_pad(plain + m,16)
    let cipher = aes_cbc_encrypt(keys.writeKey, keys.writeIv, p);
    let newIv = cbc_last_block(cipher,16);
    keys.writeSn = keys.writeSn + 1;
    keys.writeIv = newIv;
    return cipher
}

var aes_cbc_sha_decrypt_10 = function(keys,cipher,ad) {
    let p = aes_cbc_decrypt(keys.readKey, keys.readIv, cipher);
    let plen = util.int_of_bytes(util.substr(p, p.length - 2, 2), 2);
    let sp1 = util.split(p, util.getLength(p) - plen - 1);
    let sp2 = util.split(sp1.fst, util.getLength(sp1.fst) - 20);
    let snb = util.bytes_of_int(keys.readSn,8);
    let lenb = util.bytes_of_int(util.getLength(sp2.fst),2);
    let adb = snb + ad + lenb;
    let m = hmac_sha1(keys.readMacKey,
				 adb + sp2.fst);

    let newIv = cbc_last_block(cipher, 16);
    keys.readSn = keys.readSn + 1;
    keys.readIv = newIv;
    if (m === sp2.snd)
	return {valid: true, plaintext: sp2.fst}
    else
	return {valid: false, plaintext: sp2.fst}
}

var aes_cbc_sha_encrypt_12 = function(keys,plain,ad) {
    let snb = util.bytes_of_int(keys.writeSn,8);
    let lenb = util.bytes_of_int(util.getLength(plain),2);
    let adb = snb + ad + lenb;
    let m = hmac_sha1(keys.writeMacKey, adb + plain);
    let p = cbc_pad(plain + m,16)
    let iv16 = randomBytes(16);
    let cipher = aes_cbc_encrypt(keys.writeKey, keys.writeIv, p);
    let last = cbc_last_block(cipher,16);
    keys.writeSn = keys.writeSn + 1;
    return cipher
}

var aes_cbc_sha_decrypt_12 = function(keys,cipher,ad) {
    let p = aes_cbc_decrypt(keys.readKey, keys.readIv, cipher);
    let plen = util.int_of_bytes(util.substr(p, p.length - 2, 2), 2);
    let sp1 = util.split(p, util.getLength(p) - plen - 1);
    let sp2 = util.split(sp1.fst, util.getLength(sp1.fst) - 20);
    let snb = util.bytes_of_int(keys.readSn,8);
    let lenb = util.bytes_of_int(util.getLength(sp2.fst),2);
    let adb = snb + ad + lenb;
    let m = hmac_sha1(keys.readMacKey,
				 adb + sp2.fst);
    keys.readSn = keys.readSn + 1;
    if (m === sp2.snd)
	return {valid: true, plaintext: sp2.fst}
    else
	return {valid: false, plaintext: sp2.fst}
}






const cert_from_pem_file = function (file) {
    const pem = fs.readFileSync(file).toString('ascii');
    const cert = new rsasign.X509();
    cert.readCertPEM(pem);
    return cert;
}
const key_from_pem_file = function (file) {
    const pem = fs.readFileSync(file).toString('ascii');
    return pem;
}
const cert_get_subject = function (cert) {
    var x = new rsasign.X509();
    x.hex = cert;
    return x.getSubjectString()
}
const cert_get_publicKey = function (cert) {
    var x = new rsasign.X509();
    x.hex = cert;
    var a = rsasign.X509.getPublicKeyHexArrayFromCertHex(cert);
    var k = new rsasign.RSAKey();
    k.setPublic(a[0], a[1]);
    return (rsasign.KEYUTIL.getPEM(k));
}
const encoding = {
    ascii: "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
    ascii_table: {
	"0": 48,
	"1": 49,
	"2": 50,
	"3": 51,
	"4": 52,
	"5": 53,
	"6": 54,
	"7": 55,
	"8": 56,
	"9": 57,
	"\x00": 0,
	"\x01": 1,
	"\x02": 2,
	"\x03": 3,
	"\x04": 4,
	"\x05": 5,
	"\x06": 6,
	"\x07": 7,
	"\b": 8,
	"\t": 9,
	"\n": 10,
	"\x0b": 11,
	"\f": 12,
	"\r": 13,
	"\x0e": 14,
	"\x0f": 15,
	"\x10": 16,
	"\x11": 17,
	"\x12": 18,
	"\x13": 19,
	"\x14": 20,
	"\x15": 21,
	"\x16": 22,
	"\x17": 23,
	"\x18": 24,
	"\x19": 25,
	"\x1a": 26,
	"\x1b": 27,
	"\x1c": 28,
	"\x1d": 29,
	"\x1e": 30,
	"\x1f": 31,
	" ": 32,
	"!": 33,
	'"': 34,
	"#": 35,
	"$": 36,
	"%": 37,
	"&": 38,
	"'": 39,
	"(": 40,
	")": 41,
	"*": 42,
	"+": 43,
	",": 44,
	"-": 45,
	".": 46,
	"/": 47,
	":": 58,
	";": 59,
	"<": 60,
	"=": 61,
	">": 62,
	"?": 63,
	"@": 64,
	"A": 65,
	"B": 66,
	"C": 67,
	"D": 68,
	"E": 69,
	"F": 70,
	"G": 71,
	"H": 72,
	"I": 73,
	"J": 74,
	"K": 75,
	"L": 76,
	"M": 77,
	"N": 78,
	"O": 79,
	"P": 80,
	"Q": 81,
	"R": 82,
	"S": 83,
	"T": 84,
	"U": 85,
	"V": 86,
	"W": 87,
	"X": 88,
	"Y": 89,
	"Z": 90,
	"[": 91,
	"\\": 92,
	"]": 93,
	"^": 94,
	"_": 95,
	"`": 96,
	"a": 97,
	"b": 98,
	"c": 99,
	"d": 100,
	"e": 101,
	"f": 102,
	"g": 103,
	"h": 104,
	"i": 105,
	"j": 106,
	"k": 107,
	"l": 108,
	"m": 109,
	"n": 110,
	"o": 111,
	"p": 112,
	"q": 113,
	"r": 114,
	"s": 115,
	"t": 116,
	"u": 117,
	"v": 118,
	"w": 119,
	"x": 120,
	"y": 121,
	"z": 122,
	"{": 123,
	"|": 124,
	"}": 125,
	"~": 126,
	"\x7f": 127,
	"\x80": 128,
	"\x81": 129,
	"\x82": 130,
	"\x83": 131,
	"\x84": 132,
	"\x85": 133,
	"\x86": 134,
	"\x87": 135,
	"\x88": 136,
	"\x89": 137,
	"\x8a": 138,
	"\x8b": 139,
	"\x8c": 140,
	"\x8d": 141,
	"\x8e": 142,
	"\x8f": 143,
	"\x90": 144,
	"\x91": 145,
	"\x92": 146,
	"\x93": 147,
	"\x94": 148,
	"\x95": 149,
	"\x96": 150,
	"\x97": 151,
	"\x98": 152,
	"\x99": 153,
	"\x9a": 154,
	"\x9b": 155,
	"\x9c": 156,
	"\x9d": 157,
	"\x9e": 158,
	"\x9f": 159,
	"\xa0": 160,
	"\xa1": 161,
	"\xa2": 162,
	"\xa3": 163,
	"\xa4": 164,
	"\xa5": 165,
	"\xa6": 166,
	"\xa7": 167,
	"\xa8": 168,
	"\xa9": 169,
	"\xaa": 170,
	"\xab": 171,
	"\xac": 172,
	"\xad": 173,
	"\xae": 174,
	"\xaf": 175,
	"\xb0": 176,
	"\xb1": 177,
	"\xb2": 178,
	"\xb3": 179,
	"\xb4": 180,
	"\xb5": 181,
	"\xb6": 182,
	"\xb7": 183,
	"\xb8": 184,
	"\xb9": 185,
	"\xba": 186,
	"\xbb": 187,
	"\xbc": 188,
	"\xbd": 189,
	"\xbe": 190,
	"\xbf": 191,
	"\xc0": 192,
	"\xc1": 193,
	"\xc2": 194,
	"\xc3": 195,
	"\xc4": 196,
	"\xc5": 197,
	"\xc6": 198,
	"\xc7": 199,
	"\xc8": 200,
	"\xc9": 201,
	"\xca": 202,
	"\xcb": 203,
	"\xcc": 204,
	"\xcd": 205,
	"\xce": 206,
	"\xcf": 207,
	"\xd0": 208,
	"\xd1": 209,
	"\xd2": 210,
	"\xd3": 211,
	"\xd4": 212,
	"\xd5": 213,
	"\xd6": 214,
	"\xd7": 215,
	"\xd8": 216,
	"\xd9": 217,
	"\xda": 218,
	"\xdb": 219,
	"\xdc": 220,
	"\xdd": 221,
	"\xde": 222,
	"\xdf": 223,
	"\xe0": 224,
	"\xe1": 225,
	"\xe2": 226,
	"\xe3": 227,
	"\xe4": 228,
	"\xe5": 229,
	"\xe6": 230,
	"\xe7": 231,
	"\xe8": 232,
	"\xe9": 233,
	"\xea": 234,
	"\xeb": 235,
	"\xec": 236,
	"\xed": 237,
	"\xee": 238,
	"\xef": 239,
	"\xf0": 240,
	"\xf1": 241,
	"\xf2": 242,
	"\xf3": 243,
	"\xf4": 244,
	"\xf5": 245,
	"\xf6": 246,
	"\xf7": 247,
	"\xf8": 248,
	"\xf9": 249,
	"\xfa": 250,
	"\xfb": 251,
	"\xfc": 252,
	"\xfd": 253,
	"\xfe": 254,
	"\xff": 255
    },
    b2h: function (c) {
	var t = '0123456789abcdef';
	var a = (c >> 4) & 15;
	var b = c & 15;
	return (
	    ((a >>>= 0) < t.length ? t[a] : "0") + ((b >>>= 0) < t.length ? t[b] :
						    "0"));
    },
    b2a: function (n) {
	var a = this.ascii + '';
	return (n >>>= 0) < a.length ? a[n] : "\x00";
    },
    a2b: function (a) {
	var t = this.ascii_table;
	return (a.length == 1 && a <= "\xFF" ? t[a] : 0);
    },
    astr2hstr: function (s) {
	var res = '',
	    i = 0,
	    s = s + '';
	for (i = 0; i < s.length; i++) {
	    res += this.b2h(this.a2b(s[i]));
	}
	return res;
    },
    hstr2astr: function (s) {
	var i = 0,
	    u = 0,
	    c = '',
	    res = "",
	    t = this.ascii + '',
	    s = s + '';
	for (i = 0; i < s.length; i++) {
	    if (!(i & 1)) c = s[i];
	    else {
		u = +('0x' + c + s[i]);
		res += (u >>>= 0) < t.length ? t[u] : "\x00";
	    }
	}
	return res;
    }
};
const BigInteger = {
    BI_DB: 28,
    BI_DM: 268435455,
    BI_DV: 268435456,
    BI_FV: 4503599627370496,
    BI_F1: 24,
    BI_F2: 4,
    /** Create a new BigInteger initialized from the given hex value.
     * @param {Array} Byte representation of initial value.
     * @returns {BigInteger} A BigInteger structure.
     */
    am: function (th, i, x, w, j, c, n) {
	var a = th.array,
	    b = w.array,
	    l = 0,
	    m = 0,
	    xl = x & 0x3fff,
	    xh = x >> 14,
	    h = 0;
	while (--n >= 0) {
	    l = a[i & 255] & 0x3fff;
	    i
	    h = a[i++ & 255] >> 14;
	    m = xh * l + h * xl;
	    l = xl * l + ((m & 0x3fff) << 14) + b[j & 255] + c;
	    c = (l >> 28) + (m >> 14) + xh * h;
	    b[j++ & 255] = l & 0xfffffff;
	}
	return c;
    },
    create: function (v) {
	var neg = false,
	    p = '',
	    b = '',
	    s = '' + v,
	    i = 0,
	    j = 0,
	    a = [
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	    ],
	    res = {
		array: a,
		t: 0,
		s: 0
	    };
	i = s.length;
	while (--i >= 0) {
	    b = (i >>>= 0) < s.length ? s[i] : "0";
	    if (i == 0 && b == '-') {
		neg = true;
		continue;
	    }
	    p = b + p;
	    if (j++ % 7 == 6) {
		a[res.t++ & 255] = +('0x' + p);
		p = '';
	    }
	}
	if (!!p) a[res.t++ & 255] = +('0x' + p);
	p = '';
	if (neg) res = this.negate(res);
	this.clamp(res);
	return res;
    },
    /** Copy the value of a BigInteger to another.
     * @param {BigInteger} source Integer to copy.
     * @param {BigInteger} target Target of copy.
     * @returns {BigInteger} Returns the target of the copy.
     */
    copyTo: function (th, r) {
	var ta = th.array,
	    ra = r.array,
	    i = 0;
	for (i = th.t - 1; i >= 0; --i) ra[i & 255] = ta[i & 255];
	r.t = th.t;
	r.s = th.s;
	return r;
    },
    clamp: function (th) {
	var a = th.array,
	    c = th.s & this.BI_DM;
	while (th.t > 0 && a[(th.t - 1) & 255] == c) --th.t;
    },
    /** Convert BigInteger to its hex representation.
     * @param {BigInteger} n Number to convert
     * @returns {string} Hex representation of n, as a string.
     */
    toString: function (th) {
	var a = th.array,
	    c = 0,
	    i = 0,
	    j = 0,
	    hex = '0123456789abcdef',
	    k = 0,
	    nz = false,
	    h = '',
	    res = '';
	if (th.s < 0) return "-" + this.toString(this.negate(th));
	for (i = th.t - 1; i >= 0; i--) {
	    c = a[i & 255];
	    for (j = 24; j >= 0; j -= 4) {
		k = (c >> j) & 15;
		h = (k >>>= 0) < hex.length ? hex[k] : "0";
		if (h != '0') nz = true;
		if (nz) res += h;
	    }
	}
	return !res ? '0' : res;
    },
    /** Change sign of number.
     * @param {BigInteger} n Input number
     * @returns {BigInteger} A newly allocated BigInteger with opposite value
     */
    negate: function (th) {
	var t = this.create(''),
	    z = this.create('');
	this.subTo(z, th, t);
	return t;
    },
    /** Absolute value.
     * @param {BigInteger} n Input number
     * @returns {BigInteger} If n is positive, returns n, otherwise return negate(n)
     */
    abs: function (th) {
	return th.s < 0 ? this.negate(th) : th;
    },
    /** Exclusive OR of two numbers
     * @param {BigInteger} n First operand
     * @param {BigInteger} m Second operand
     * @returns {BigInteger} n xor m
     */
    xor: function (th, a) {
	var x = th.array,
	    y = a.array,
	    r = this.create([0]),
	    z = r.array,
	    i = (th.t > a.t) ? th.t : a.t;
	r.t = i;
	while (--i >= 0) z[i & 255] = x[i & 255] ^ y[i & 255];
	return r;
    },
    /** Comparison of BigInteger.
     * @param {BigInteger} n First value
     * @param {BigInteger} m Second value
     * @returns {number} A negative value if n<m, 0 if n=m and a positive value otherwise.
     */
    compareTo: function (th, a) {
	var x = th.array,
	    y = a.array,
	    i = th.t,
	    r = th.s - a.s,
	    s = th.t - a.t;
	if (!!r) return r;
	if (!!s) return s;
	while (--i >= 0)
	    if ((r = (x[i & 255] - y[i & 255])) != 0) return r;
	return 0;
    },
    /** Index of the first non-zero bit starting from the least significant bit.
     * @param {number} n  Input number
     * @returns {number} the bit length of n. Can behave strangely on negative and float values.
     */
    nbits: function (x) {
	var r = 1,
	    t = 0;
	if ((t = x >>> 16) != 0) {
	    x = t;
	    r += 16;
	}
	if ((t = x >> 8) != 0) {
	    x = t;
	    r += 8;
	}
	if ((t = x >> 4) != 0) {
	    x = t;
	    r += 4;
	}
	if ((t = x >> 2) != 0) {
	    x = t;
	    r += 2;
	}
	if ((t = x >> 1) != 0) {
	    x = t;
	    r += 1;
	}
	return r;
    },
    /** Index of first non-zero bit starting from the LSB of the given BigInteger.
     * @param {BigInteger} n Input BigInteger
     * @returns {number} the bit length of n.
     */
    bitLength: function (th) {
	var a = th.array;
	if (th.t <= 0) return 0;
	return this.BI_DB * (th.t - 1) + this.nbits(a[(th.t - 1) & 255] ^ (th.s &
									   this.BI_DM));
    },
    DLshiftTo: function (th, n:number, r) {
	var a = th.array,
	    b = r.array,
	    i = 0;
	for (i = th.t - 1; i >= 0; --i) b[(i + n) & 255] = a[i & 255];
	for (i = n - 1; i >= 0; --i) b[i & 255] = 0;
	r.t = th.t + n;
	r.s = th.s;
    },
    DRshiftTo: function (th, n, r) {
	var a = th.array,
	    b = r.array,
	    i = 0;
	for (i = n; i < th.t; ++i) b[(i - n) & 255] = a[i & 255];
	r.t = th.t > n ? th.t - n : 0;
	r.s = th.s;
    },
    /** Logical shift to the left
     * @param {BigInteger} n Input number
     * @param {number} k Number of positions to shift
     * @param {BigInteger} r Target number to store the result to
     */
    LshiftTo: function (th, n, r) {
	var a = th.array,
	    b = r.array,
	    bs = n % this.BI_DB,
	    cbs = this.BI_DB - bs,
	    bm = (1 << cbs) - 1,
	    ds = (n / this.BI_DB) | 0,
	    c = (th.s << bs) & this.BI_DM,
	    i = 0;
	for (i = th.t - 1; i >= 0; --i) b[(i + ds + 1) & 255] = (a[i & 255] >>
								 cbs) | c, c = (a[i & 255] & bm) << bs;
	for (i = ds - 1; i >= 0; --i) b[i & 255] = 0;
	b[ds & 255] = c;
	r.t = th.t + ds + 1;
	r.s = th.s;
	this.clamp(r);
    },
    /** Logical shift to the right.
     * @param {BigInteger} n Input number
     * @param {number} k Number of positions to shift
     * @param {BigInteger} r Target number to store the result to
     */
    RshiftTo: function (th, n, r) {
	var a = th.array,
	    b = r.array,
	    i = 0,
	    bs = n % this.BI_DB,
	    cbs = this.BI_DB - bs,
	    bm = (1 << bs) - 1,
	    ds = (n / this.BI_DB) | 0;
	r.s = th.s;
	if (ds >= th.t) {
	    r.t = 0;
	    return;
	}
	b[0] = a[ds & 255] >> bs;
	for (i = ds + 1; i < th.t; ++i) b[(i - ds - 1) & 255] |= (a[i & 255] &
								  bm) << cbs,
	b[(i - ds) & 255] = a[i & 255] >> bs;
	if (bs > 0) b[(th.t - ds - 1) & 255] |= (th.s & bm) << cbs;
	r.t = th.t - ds;
	this.clamp(r);
    },
    /** Subtraction of BigIntegers.
     * @param {BigInteger} n First operand
     * @param {BigInteger} m Second operand
     * @param {BigInteger} r Target number to store the result (n-m) to.
     */
    subTo: function (th, y, r) {
	var a = th.array,
	    z = r.array,
	    b = y.array,
	    i = 0,
	    c = 0,
	    m = y.t < th.t ? y.t : th.t;
	while (i < m) {
	    c += a[i & 255] - b[i & 255];
	    z[i++ & 255] = c & this.BI_DM;
	    c >>= this.BI_DB;
	}
	if (y.t < th.t) {
	    c -= y.s;
	    while (i < th.t) {
		c += a[i & 255];
		z[i++ & 255] = c & this.BI_DM;
		c >>= this.BI_DB;
	    }
	    c += th.s;
	} else {
	    c += th.s;
	    while (i < y.t) {
		c -= b[i & 255];
		z[i++ & 255] = c & this.BI_DM;
		c >>= this.BI_DB;
	    }
	    c -= y.s;
	}
	r.s = (c < 0) ? -1 : 0;
	if (c < -1) z[i++ & 255] = this.BI_DV + c;
	else if (c > 0) z[i++ & 255] = c;
	r.t = i;
	this.clamp(r);
    },
    /** Multiplication of BigIntegers.
     * @param {BigInteger} n First operand
     * @param {BigInteger} m Second operand
     * @param {BigInteger} r Target number to store the result (n*m) to.
     */
    multiplyTo: function (th, a, r) {
	var u = th.array,
	    v = r.array,
	    x = this.abs(th),
	    y = this.abs(a),
	    w = y.array,
	    i = x.t;
	r.t = i + y.t;
	while (--i >= 0) v[i & 255] = 0;
	for (i = 0; i < y.t; ++i) v[(i + x.t) & 255] = this.am(x, 0, w[i & 255],
							       r, i, 0, x.t);
	r.s = 0;
	this.clamp(r);
	if (th.s != a.s) this.subTo(this.create(''), r, r);
    },
    /** Squaring of a BigInteger.
     * @param {BigInteger} n First operand
     * @param {BigInteger} r Target number to store the result (n*n) to.
     */
    squareTo: function (th, r) {
	var x = this.abs(th),
	    u = x.array,
	    v = r.array,
	    i = (r.t = 2 * x.t),
	    c = 0;
	while (--i >= 0) v[i & 255] = 0;
	for (i = 0; i < x.t - 1; ++i) {
	    c = this.am(x, i, u[i & 255], r, 2 * i, 0, 1);
	    if ((v[(i + x.t) & 255] += this.am(x, i + 1, 2 * u[i & 255], r, 2 * i +
					       1, c, x.t - i - 1)) >= this.BI_DV) v[(i + x.t) & 255] -= this.BI_DV, v[
						   (i + x.t + 1) & 255] = 1;
	}
	if (r.t > 0) v[(r.t - 1) & 255] += this.am(x, i, u[i & 255], r, 2 * i, 0,
						   1);
	r.s = 0;
	this.clamp(r);
    },
    /** Euclidean division of two BigIntegers.
     * @param {BigInteger} n First operand
     * @param {BigInteger} m Second operand
     * @returns {BigInteger[]} Returns an array of two BigIntegers: first element is the quotient, second is the remainder.
     */
    divRem: function (th, div) {
	var m = this.abs(div),
	    t = this.abs(th),
	    ma = m.array,
	    ta = th.array,
	    ts = th.s,
	    ms = m.s,
	    nsh = this.BI_DB - this.nbits(ma[(m.t - 1) & 255]),
	    q = this.create('0'),
	    r = this.create('0'),
	    qa = q.array,
	    ra = r.array,
	    qd = 0,
	    y = this.create('0'),
	    ya = y.array,
	    ys = 0,
	    y0 = 0,
	    yt = 0,
	    i = 0,
	    j = 0,
	    d1 = 0,
	    d2 = 0,
	    e = 0;
	if (t.t < m.t) this.copyTo(th, r);
	if (!m.t || t.t < m.t) return [q, r];
	if (nsh > 0) {
	    this.LshiftTo(m, nsh, y);
	    this.LshiftTo(t, nsh, r);
	} else {
	    this.copyTo(m, y);
	    this.copyTo(m, r);
	}
	ys = y.t;
	y0 = ya[(ys - 1) & 255];
	if (y0 == 0) return [q, r];
	yt = y0 * (1 << this.BI_F1) + ((ys > 1) ? ya[(ys - 2) & 255] >> this.BI_F2 :
				       0);
	d1 = this.BI_FV / yt, d2 = (1 << this.BI_F1) / yt, e = 1 << this.BI_F2;
	i = r.t, j = i - ys;
	this.DLshiftTo(y, j, q);
	if (this.compareTo(r, q) >= 0) {
	    ra[r.t++ & 255] = 1;
	    this.subTo(r, q, r);
	}
	this.DLshiftTo(this.create('1'), ys, q);
	this.subTo(q, y, y);
	while (y.t < ys) ya[y.t++ & 255] = 0;
	while (--j >= 0) {
	    qd = (ra[--i & 255] == y0) ? this.BI_DM : (ra[i & 255] * d1 + (ra[(i -
									       1) & 255] + e) * d2) | 0;
	    if ((ra[i & 255] += this.am(y, 0, qd, r, j, 0, ys)) < qd) {
		this.DLshiftTo(y, j, q);
		this.subTo(r, q, r);
		while (ra[i & 255] < --qd) this.subTo(r, q, r);
	    }
	}
	this.DRshiftTo(r, ys, q);
	if (ts != ms) this.subTo(this.create('0'), q, q);
	r.t = ys;
	this.clamp(r);
	if (nsh > 0) this.RshiftTo(r, nsh, r);
	if (ts < 0) this.subTo(this.create('0'), r, r);
	return [q, r];
    },
    /** Modular remainder of an integer division.
     * @param {BigInteger} n First operand
     * @param {BigInteger} m Second operand
     * @returns {BigInteger} n mod m
     */
    mod: function (th, a) {
	var r = this.divRem(this.abs(th), a)[1];
	if (th.s < 0 && this.compareTo(r, this.create('0')) > 0) this.subTo(a, r,
									    r);
	return r;
    },
    invDigit: function (th) {
	var a = th.array,
	    x = a[0],
	    y = x & 3;
	if (th.t < 1 || !(x & 1)) return 0;
	y = (y * (2 - (x & 0xf) * y)) & 0xf;
	y = (y * (2 - (x & 0xff) * y)) & 0xff;
	y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff;
	y = (y * (2 - x * y % this.BI_DV)) % this.BI_DV;
	return (y > 0) ? this.BI_DV - y : -y;
    },
    /** Extract a single bit from a BigInteger.
     * @param {BigInteger} x value to extract bit from.
     * @param {number} n index of the bit to return.
     * @returns {number} 0 or 1.
     */
    getBit: function (th, n) {
	var j = Math.floor(n / this.BI_DB)
	if (j >= th.t) {
	    return (th.s != 0)
	}
	return (th.array[j] >> (n % this.BI_DB)) & 1
    },
    /** Modular exponentiation using Montgomery reduction.
     * @param {BigInteger} x Value to exponentiate
     * @param {BigInteger} e Exponent
     * @param {BigInteger} n Modulus - must be odd
     * @re`<turns {BigInteger} x^e mod n
     */
    expMod: function (th, e, m) {
	var r = this.create('1'),
	    r2 = this.create('0'),
	    eb = e.array[(e.t - 1) & 255],
	    g = this.Mconvert(th, m),
	    i = this.bitLength(e) - 1,
	    j = 0,
	    t = r;
	if (this.compareTo(e, r) < 0) return r;
	this.copyTo(g, r);
	while (--i >= 0) {
	    j = i % this.BI_DB;
	    this.squareTo(r, r2);
	    this.Mreduce(r2, m);
	    if ((eb & (1 << j)) != 0) {
		this.multiplyTo(r2, g, r);
		this.Mreduce(r, m);
	    } else {
		t = r;
		r = r2;
		r2 = t;
	    }
	    if (!j) eb = e.array[(i / this.BI_DB - 1) & 255];
	}
	return this.Mrevert(r, m);
    },
    Mconvert: function (th, m) {
	var s = this.create('0'),
	    r = (this.DLshiftTo(this.abs(th), m.t, s), this.divRem(s, m))[1];
	if (th.s < 0 && this.compareTo(r, this.create('0')) > 0) this.subTo(m, r,
									    r);
	return r;
    },
    Mreduce: function (th, m) {
	var mp = this.invDigit(m),
	    mpl = mp & 0x7fff,
	    mph = mp >> 15,
	    a = th.array,
	    um = (1 << (this.BI_DB - 15)) - 1,
	    mt2 = 2 * m.t,
	    i = 0,
	    j = 0,
	    u0 = 0;
	while (th.t <= mt2) a[th.t++ & 255] = 0;
	for (i = 0; i < m.t; ++i) {
	    j = a[i & 255] & 0x7fff;
	    u0 = (j * mpl + (((j * mph + (a[i & 255] >> 15) * mpl) & um) << 15)) &
		this.BI_DM;
	    j = i + m.t;
	    a[j & 255] += this.am(m, 0, u0, th, i, 0, m.t);
	    while (a[j & 255] >= this.BI_DV) {
		a[j & 255] -= this.BI_DV;
		a[++j & 255]++;
	    }
	}
	this.clamp(th);
	this.DRshiftTo(th, m.t, th);
	if (this.compareTo(th, m) >= 0) this.subTo(th, m, th);
	return th;
    },
    Mrevert: function (th, m) {
	var c = this.create('0');
	this.copyTo(th, c);
	return this.Mreduce(c, m);
    },
    bitwiseTo: function (th, a, op, r) {
	var i, f, m = Math.min(a.t, th.t);
	for (i = 0; i < m; ++i) r.array[i] = op(th.array[i], a.array[i]);
	if (a.t < th.t) {
	    f = a.s & this.BI_DM;
	    for (i = m; i < th.t; ++i) r.array[i] = op(th.array[i], f);
	    r.t = th.t;
	} else {
	    f = th.s & this.BI_DM;
	    for (i = m; i < a.t; ++i) r.array[i] = op(f, a.array[i]);
	    r.t = a.t;
	}
	r.s = op(th.s, a.s);
	this.clamp(r);
    },
    lAnd: function (a, b) {
	var r = this.create('0');
	var op_and = function (x, y) {
	    return x & y;
	}
	this.bitwiseTo(b, a, op_and, r);
	return r;
    },
    changeBit: function (th, n, op) {
	var r = this.create('1');
	var l = this.create('0');
	this.LshiftTo(r, n, l);
	this.bitwiseTo(th, l, op, l);
	return l;
    },
    clearBit: function (th, n) {
	var op_andnot = function (x, y) {
	    return x & ~y
	}
	return this.changeBit(th, n, op_andnot);
    },
    setBit: function (th, n) {
	var op_or = function (x, y) {
	    return x | y
	}
	return this.changeBit(th, n, op_or);
    },
    flipHexString: function (s) {
	if (s.length % 2) {
	    s = '0' + s
	}
	var r = '';
	var i = 0;
	for (i = s.length - 1; i > 0; i -= 2) {
	    r += s[i - 1] + s[i]
	}
	return r
    },
    toFlippedString: function (th) {
	return this.flipHexString(this.toString(th));
    }
};
/**
 * RSA Public Key cryptography
 * @author Antoine Delignat-Lavaud
 * @description
 * <p>An implementation of PKCS#1 v2.1.</p>
 * <p>The main difference with other PKCS#1 implementations
 * is the format of the keys. Instead of using ASN.1 for
 * encoding, the keys are stored in an equivalent JSON object.
 * For a public key, the fields are 'n' for the modulus and
 * 'e' for the public exponent. In addition, a private key must
 * contain the CRT values 'dmp1', 'dmq1', 'p', 'q' and 'iqmp'
 * (the private exponent 'd' is not required because it is not
 * used for decryption; using BigInteger it is easy to compute
 * 'dmp1', 'dmq1' and 'iqmp' from 'd', 'p' and 'q').</p>
 * <p>Use the following PHP script (requires the openssl extension)
 * to convert a PKCS#1 key to JSON:</p>
 * <pre>#!/usr/bin/env php
 * &lt;?
 * if(count($argv)&lt;2) die("Usage: {$argv[0]} file.pem\n");
 * $f = "file://{$argv[1]}";
 * if(!($k = openssl_pkey_get_private($f)))
 *  dir("Failed to import private key {$argv[1]}.\n");
 * $d = openssl_pkey_get_details($k);
 * $pk = $d['rsa'];
 * foreach($pk as $p=&gt;$v) $pk[$p] = bin2hex($v);
 * echo json_encode($pk)."\n";</pre>
 * @requires BigInteger
 * @requires encoding
 * @requires hashing
 * @namespace
 */
var rsa_pss = {
    /** Label of OAEP encryption, an ASCII string empty by default.
     * Can be of any length since it will be hash using rsa.encryption_hash
     */
    label: '',
    /** Salt of PSS signature, an ASCII string empty by default.
     * The max length is n-h-2 where n is the modulus size in bytes and h the
     * size in bytes of the output of the hash function.
     */
    salt: '',
    /** If something fails, this code provides information about the error.
     * <table width="100%"><tr><th>Code</th><th>Description</th></tr>
     * <tr><th>0</td><td>No error.</td></tr>
     * <tr><th>1</td><td>Message is too long for the modulus.</td></tr>
     * <tr><th>2</td><td>Invalid length of the input to decrypt or verify.</td></tr>
     * <tr><th>3</td><td>Top byte/bit is not zero after decryption/verification.</td></tr>
     * <tr><th>4</td><td>Incorrect padding of encrypted/signature data.</td></tr>
     * <tr><th>5</td><td>Bad label of OAEP encryption.</td></tr>
     * <tr><th>6</td><td>PSS salt is too long for modulus.</td></tr>
     * <tr><th>7</td><td>Invalid PSS padding byte in PSS signature.</td></tr>
     * </table> */
    error_code: 0,
    /** RSASSA-PSS-SIGN signature using rsa.signature_hash.
     * @param {string} message ASCII string containing the data to sign
     * @param {privateKey} priv Private Key
     * @returns {string} Hex string representing a PSS signature for the data
     */
    /** MGF1 message generating function. Underlying hash function is rsa.mgf_hash
     * @param {string} seed Hex string containing the seed for message generation
     * @param {number} length Length n of the requested message in bytes
     * @returns {string} Hex string of the desired length
     */
    MGF: function (seed, length) {
	var res = '',
	    c = '',
	    i = 0,
	    j = 0,
	    len = length << 1,
	    hs = 32,
	    n = (length / hs | 0) + (!(length % hs) ? 0 : 1);
	for (i = 0; i < n; i++) {
	    for (c = '', j = 0; j < 4; j++) c += encoding.b2h((i >> (24 - 8 * j)) &
							      255);
	    c = encoding.astr2hstr(sha256_rsa(encoding.hstr2astr(seed + c)));
	    for (j = 0; j < c.length; j++) {
		res += c[j];
		if (res.length == len) return res;
	    }
	}
	return res;
    },
    sign: function (message, priv) {
	var m = sha256_rsa(message + ''),
	    DB = '',
	    sm = '',
	    pad = '',
	    salt = this.salt + '',
	    sl = salt.length,
	    i = 0,
	    hs = 32,
	    n = BigInteger.bitLength(BigInteger.create(priv.n + '')) >> 3;
	if (n - hs - 2 < sl) {
	    this.error_code = 6;
	    return ""
	}
	m = encoding.astr2hstr(sha256("\x00\x00\x00\x00\x00\x00\x00\x00" + m + salt));
	sm = "01" + encoding.astr2hstr(salt);
	for (i = sm.length >> 1; i < n - sl - hs - 2; i++) pad += "00";
	DB = this.MGF(m, n - hs - 1);
	// Most significant bit - PSS could be using a byte like OAEP...
	sm = (+('0x' + (0 < DB.length ? DB[0] : "0")) >> 3 == 0 ? "00" : "80") +
	    pad + sm;
	DB = BigInteger.toString(BigInteger.xor(BigInteger.create(DB),
						BigInteger.create(sm)));
	DB += m + 'bc';
	DB = this._private(DB, priv);
	if (!!(DB.length & 1)) DB = '0' + DB;
	this.error_code = 0;
	return DB;
    },
    /** EMSA-PKCS1-v1_5-ENCODE
     * @private
     */
    _pkcs1_sig_pad: function (m, n) {
	var h = this.signature_hash,
	    m = sha256_rsa(m + ''),
	    res = '',
	    pad = '',
	    i = 0;
	// DER octet string of hash
	m = "04" + encoding.b2h(h.size) + encoding.astr2hstr(m);
	res = '608648016503040201';
	res = '06' + encoding.b2h(res.length >> 1) + res + '0500';
	res = '30' + encoding.b2h(res.length >> 1) + res + m;
	res = '0030' + encoding.b2h(res.length >> 1) + res;
	for (i = res.length >> 1; i < n - 2; i++) pad += "ff";
	return '0001' + pad + res;
    },
    /** RSASSA-PKCS1-V1_5-SIGN signature using rsa.signature_hash.
     * @param {string} message ASCII string containing the data to sign
     * @param {privateKey} priv Private Key
     * @returns {string} Hex string representing a PKCS1v1.5 signature for the data
     */
    sign_pkcs1_v1_5: function (message, priv) {
	var res = '',
	    n = BigInteger.bitLength(BigInteger.create(priv.n + '')) >> 3;
	res = this._private(this._pkcs1_sig_pad(message, n), priv);
	if (!!(res.length & 1)) res = '0' + res;
	this.error_code = 0;
	return res;
    },
    /** RSASSA-PSS-VERIFY signature verification using rsa.signature_hash.
     * @param {string} data ASCII string containing the signed data
     * @param {string} signature Hex string containing the signature of the data
     * @param {publicKey} pub Public key of the expected sender
     * @returns {boolean} whether s is a valid signature for m from pub
     */
    verify: function (data, signature, pub) {
	var hs = 32,
	    m = sha256_rsa(data + ''),
	    s = signature + '',
	    N = BigInteger.create(pub.n + ''),
	    k = s.length >> 1,
	    E = BigInteger.create(pub.e + ''),
	    n = BigInteger.bitLength(N) >> 3,
	    i = 0,
	    DB = '',
	    sm = '',
	    pad = '',
	    f = false;
	if (k != n) {
	    this.error_code = 2;
	    return false
	}
	s = BigInteger.toString(BigInteger.expMod(BigInteger.create(s), E, N));
	while (s.length != 2 * n) s = '0' + s;
	if (+(0 < s.length ? s[0] : '0') >> 3 != 0) {
	    this.error_code = 3;
	    return false
	}
	for (i = 0; i < s.length; i++) {
	    if (i < 2 * (n - hs - 1)) DB += s[i];
	    else if (i < 2 * (n - 1)) sm += s[i];
	    else pad += s[i];
	}
	if (pad != "bc") {
	    this.error_code = 7;
	    return false
	}
	s = sm;
	sm = this.MGF(sm, n - hs - 1);
	DB = BigInteger.toString(BigInteger.xor(BigInteger.create(DB),
						BigInteger.create(sm)));
	if (!!(DB.length & 1)) DB = '0' + DB;
	sm = "";
	for (i = 0; i < DB.length; i++) {
	    pad = DB[i];
	    if (!i) {
		if (pad != "0" && pad != "8") return false;
	    } else if (f) sm += pad;
	    else {
		if (pad == "1" && !!(i & 1)) {
		    f = true;
		    continue;
		}
		if (pad != "0") {
		    this.error_code = 4;
		    return false
		}
	    }
	}
	sm = encoding.hstr2astr(sm);
	this.error_code = 0;
	return encoding.astr2hstr(
	    sha256_rsa("\x00\x00\x00\x00\x00\x00\x00\x00" + m + sm)
	) == s;
    }
};


const server_cert = cert_from_pem_file('./certs/server_cert.pem');
const server_key = key_from_pem_file('./certs/server_key.pem');
const client_cert = cert_from_pem_file('./certs/client_cert.pem');
const client_key = key_from_pem_file('./certs/client_key.pem');


module.exports = {
    encoding: encoding,
    nonce: nonce,
    tls12_prf_label: tls12_prf_label,
    deriveKeys_gcm_13: deriveKeys_gcm_13,
    deriveKeys_gcm_12: deriveKeys_gcm_12,
    deriveKeys_cbc_12: deriveKeys_cbc_12,
    deriveKeys_cbc_10: deriveKeys_cbc_10,
    aes_gcm_encrypt_13: aes_gcm_encrypt_13,
    aes_gcm_decrypt_13: aes_gcm_decrypt_13,
    aes_gcm_encrypt_12: aes_gcm_encrypt_12,
    aes_gcm_decrypt_12: aes_gcm_decrypt_12,
    aes_cbc_sha_encrypt_12: aes_cbc_sha_encrypt_12,
    aes_cbc_sha_decrypt_12: aes_cbc_sha_decrypt_12,
    aes_cbc_sha_encrypt_10: aes_cbc_sha_encrypt_10,
    aes_cbc_sha_decrypt_10: aes_cbc_sha_decrypt_10,
    hmac_sha256: hmac_sha256,
    hmac_sha1: hmac_sha1,
    hmac_md5: hmac_md5,
    sha256: sha256,
    sha1: sha1,
    md5: md5,
    p256r1_keygen: p256r1_keygen,
    p256r1_public: p256r1_public,
    p256r1_getX: p256r1_getX,
    p256r1_ecdh: p256r1_ecdh,
    ff2048_keygen: ff2048_keygen,
    ff2048_public: ff2048_public,
    ff2048_dh: ff2048_dh,
    rsa_md5: rsa_md5,
    rsa_sha1: rsa_sha1,
    rsa_sha256: rsa_sha256,
    rsa_sha256_verify: rsa_sha256_verify,
    rsa_pss_sha256: rsa_pss_sha256,
    rsa_pss_sha256_verify: rsa_pss_sha256_verify,
    rsa_sign: rsa_sign,
    rsa_encrypt: rsa_encrypt,
    rsa_decrypt: rsa_decrypt,
    rsa_pss: rsa_pss,
    tls10_prf: tls10_prf,
    tls12_prf: tls12_prf,
    cert_from_pem_file: cert_from_pem_file,
    key_from_pem_file: key_from_pem_file,
    cert_get_subject: cert_get_subject,
    cert_get_publicKey: cert_get_publicKey,
    randomBytes: randomBytes,
    random12Bytes: random12Bytes,
    random16Bytes: random16Bytes,
    random32Bytes: random32Bytes,
    hkdf_extract: hkdf_extract,
    hkdf_expand_label: hkdf_expand_label,
    server_cert: server_cert,
    client_cert: client_cert,
    server_key: server_key,
    client_key: client_key,
    xor: xor
}
