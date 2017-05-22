/* @flow */

"use strict";
const debug = false;
//	const typechecked = require('./tls_typechecked.js');
const handshake = require('./tls_handshake.js');
const stackTrace = require('stack-trace');
const fs = require('fs');
const url = require('url');
const net = require('net');
const util = require('./util.js');
const tls_crypto = require('./tls_crypto.js');
const formats = require('./tls_formats.js');
const tls_core = require('./tls_core_protocol.js');
const tls_pp = require('./tls_prettyprint.js');
const Correct = formats.Correct;
const Incorrect = formats.Incorrect;
const AD = formats.AD;

const bindError = formats.bindError;
const mapError = formats.mapError;

const encryptRecord = function (pv: protocol_version,index,table,r:record) {
//    console.log(keys);
    switch (pv) {
    case formats.PV.TLS_1p3: {
	let f = tls_core.encrypt_13(index,table,r.fragment,r.type);
	return ({
	    type: formats.ContentType.application_data,
	    version: formats.PV.TLS_1p0,
	    fragment: f,
	})}
    default: {
	let f = tls_core.encrypt_12(index,table,r.fragment,r.type+r.version);
	return ({
	    type: r.type,
	    version: r.version,
	    fragment: f
	})}
    }
}

const decryptRecord = function (pv, index, table, c) {
    switch (pv) {
    case formats.PV.TLS_1p3: {
	let f = tls_core.decrypt_13(index,table,c.fragment);
	if (f && f.valid)
	    return Correct({
		type: f.ct,
		version: formats.PV.TLS_1p3,
		fragment: f.plaintext
	    })
	else
	    return Incorrect(AD.decode_error,
			     "decryptRecord: authenticated decryption failed");}
    default: {
	let f = tls_core.decrypt_12(index,table,c.fragment,c.type+c.version);
	if (f && f.valid)
	    return Correct({
		type: c.type,
		version: c.version,
		fragment: f.plaintext,
	    })
	else
	    return Incorrect(AD.decode_error,
			     "decryptRecord: authenticated decryption failed");}
    }
}

const logRecord = function (label:string, msg:record, pv:protocol_version, kex:string) {
    console.log(Date.now())
    if (msg.type === formats.ContentType.change_cipher_spec) {
	console.log(label + " CCS() [" + msg.version + "]");
    } else if (msg.type === formats.ContentType.application_data) {
	console.log(label + " AppData(" + util.hex2a(msg.fragment) + ") [" + msg.version +
		    "]");
    } else if (msg.type === formats.ContentType.alert) {
	console.log(label + " Alert(" + formats.AD_lookup(msg.fragment) + ") [" +
		    msg.version + "]");
    }
    if (msg.type === formats.ContentType.handshake) {
	let fm: result<pair<?hs_msg,string>> = formats.parseMessage(msg.fragment);
	bindError(fm,(hsmsg => {
	    let x:?hs_msg = hsmsg.fst;
	    if (x == null)
		throw new Error ("expected hs_msg")
	    else {
		let y = x;
		    return bindError(formats.parseHandshakeMessage(x, pv, kex),(m => {
		    y.pl = m;
		    console.log(label + " HS(" + JSON.stringify(tls_pp.printHandshakeMessage(
			y), null, '  ') + ") [" + msg.version + "]");
		    return Correct(undefined);
		}))}
	}));
    }
}
const outputRecord = function (cipherState:cipher_state,msg:record) {
    logRecord("Sending", msg, cipherState.params.pv, cipherState.params.kex);
    if (cipherState.write == true) {
	let index;
	if (cipherState.role === "client") index = cipherState.params.cr;
	else index = cipherState.params.sr;
	msg = encryptRecord(cipherState.params.pv, index, cipherState.write_keys, msg);
    }
    let res = formats.serializeRecord(msg);
    if (msg.type == formats.ContentType.change_cipher_spec) {
	if (cipherState.write_keys == "") {
	    throw new Error("Unexpected CCS, aborting");
	}
	cipherState.write = true;
    }
    return res;
}

const inputRecord = function (cipherState:cipher_state, msg: record) {
    let res = msg;
    if (cipherState.read == true) {
	let index;
	if (cipherState.role === "client") index = cipherState.params.cr;
	else index = cipherState.params.sr;
	let dec = decryptRecord(cipherState.params.pv,index,cipherState.read_keys, msg);
	
	if (dec.result === 'Error') {
	    throw new Error("Could not decrypt record, aborting - " + JSON.stringify(
		msg
	    ));
	} else if (dec.result === 'Correct') {
	    res = dec.value;
	}
    };
    logRecord("Received", res, cipherState.params.pv, cipherState.params.kex);
	if (res.type === formats.ContentType.application_data) {
		cipherState.payload += util.hex2a(res.fragment);
	}
    return res;
}
const TLS_client_scenario = function (sn:string, p:number, cb:(string=>void)) {
	const parsed = {};
	let path = '/';
	if (/^https/.test(sn)) {
		path = url.parse(sn).path;
		sn = url.parse(sn).hostname;
	}
    tls_client(sn, path, p, handshake.TLS_client_callbacks, cb);
}
const TLS_server_scenario = function (p:number, cb:(string => void)) {
    tls_server(p, handshake.TLS_server_callbacks,cb)
}

const tls_client = function (host:string, path:string, port:number, callbacks, close_cb:(string=>void)) {
    let cipherState = handshake.defaultCipherState();
//    let session = Sessions[host];
//    if (session) cipherState.session = session;
    cipherState.host = host;
    cipherState.path = path;
    let record_buf = "";
    let hs_buf = "";
    let hs_state = 0;
    let hs_msgs = [];
    const client = net.connect({port:port, host:host});
    client.setEncoding('hex');
    const sendRecord = function (msg) {
	client.write(outputRecord(cipherState, msg, false), 'hex')
    }
    client.on("connect", () => {
	console.log('Connected');
	if (hs_state != 0) throw new Error(
	    "sending client hello when state != 0");
	if (callbacks.hs_send_client_hello != undefined) {
	    let send = callbacks.hs_send_client_hello(cipherState);
	    send.forEach(sendRecord);
	}
	if (callbacks.hs_send_client_finished0 != undefined &&
	    cipherState.params.pv === formats.PV.TLS_1p3) {
	    let send = callbacks.hs_send_client_finished0(cipherState);
	    send.forEach(sendRecord);
	}
	if (callbacks.app_data_send0 != undefined &&
	    cipherState.params.pv === formats.PV.TLS_1p3) {
	    let send = callbacks.app_data_send0(cipherState);
	    send.forEach(sendRecord);
	}
	hs_state = 1;
    });
    client.on('data', function (data) {
	record_buf += data;
	let more = true;
	while (more) {
	    if (util.getLength(record_buf) < 5) {
		more = false;
	    }
	    const sp = formats.splitRecord(record_buf);
	    let res = sp;
	    if (res.result === 'Correct') {
		if (debug) {
		    console.log("Received:", JSON.stringify(res.value.fst, null, "\t"));
		}
		deliver(inputRecord(cipherState, res.value.fst, true));
		record_buf = res.value.snd;
		more = true;
	    } else if (res.result === "Error") {
		if (debug) {
		    console.log("Error:", JSON.stringify(sp, null, "\t"));
		}
		more = false;
	    }
	}
    });
    client.on('close', function () {
	console.log('Connection closed');
	var payload = cipherState.payload;
	cipherState = handshake.defaultCipherState();
	if (close_cb) close_cb(payload);
    });
    const deliver = function (msg) {
	if (cipherState.require_alert && msg.type != formats.ContentType.alert) {
	    console.log("Alert expected, but non-alert received.");
	    return;
	}
	if (msg.type === formats.ContentType.alert) {
	    if (cipherState.require_alert) {
		console.log("Alert expected and received.");
	    }
	    if (msg.fragment.startsWith("02")) {
		console.log("Fatal alert: closing connection");
		client.end();
	    }
	}
	if (msg.type === formats.ContentType.change_cipher_spec) {
	    if (hs_state != 3) {
		throw new Error("Server CCS received when hs_state != 3");
	    }
	    if (cipherState.read_keys == "") {
		throw new Error("Unexpected CCS, aborting");
	    }
	    cipherState.read = true;
	    hs_state = 4;
	}
	if (msg.type === formats.ContentType.application_data) {
	    if (hs_state != 5) {
		console.log('hs_state =', hs_state);
		throw new Error("App Data received when hs_state != 5");
	    }
	    if (cipherState.read == false) {
		throw new Error("Unexpected app data, aborting");
	    }
	    if (callbacks.app_data_recv != undefined) {
		let send = callbacks.app_data_recv(msg.fragment, cipherState);
		send.forEach(sendRecord);
	    } else {
		client.end()
	    }

	}
	if (msg.type === formats.ContentType.handshake) {
	    let hsm = msg;
	    hs_buf += hsm.fragment;
	    let more = true;
	    while (more) {
		const msg = formats.parseMessage(hs_buf);
		if (msg.result !== 'Correct') {
		    more = false
		    return
		}
		if (msg.value.fst == undefined) {
		    more = false;
		    return false
		}
		let pmsg = msg.value.fst;
		more = true;
		hs_buf = msg.value.snd;
		mapError(formats.parseHandshakeMessage(pmsg, cipherState.params.pv,
						       cipherState.params.kex,true),(m => {
  							   let nm = pmsg;
							   nm.pl = m;
							   hs_msgs.push(nm);
							   if (nm.ht === formats.HT.server_hello) {
							       if (hs_state != 1) {
								   throw new Error("Server Hello received when hs_state != 1");
							       }
							       cipherState.params.pv = m.protocol_version;
							       cipherState.params.kex = formats.KEX(m.cipher_suite);
							       if (callbacks.hs_recv_server_hello != undefined) {
								   let send = callbacks.hs_recv_server_hello(
								       hs_msgs, cipherState
								   );
								   send.forEach(sendRecord);
							       }
							       hs_msgs = [];
							       hs_state = 2;
							   } else if (nm.ht === formats.HT.server_hello_done) {
							       if (hs_state != 2) {
								   throw new Error("Server Hello Done received when hs_state != 2");
							       }
							       if (callbacks.hs_recv_server_hello_done != undefined) {
								   ////								   console.log("calling shd callback");
								   let send = callbacks.hs_recv_server_hello_done(
								       hs_msgs, cipherState
								   );
								   send.forEach(sendRecord);
							       }
							       hs_msgs = [];
							       hs_state = 3;
							   } else if (nm.ht === formats.HT.session_ticket) {
							       callbacks.hs_recv_session_ticket(nm, cipherState);
//							       Sessions[host] = cipherState.session;
							       hs_msgs = [];
							   } else if (nm.ht === formats.HT.finished) {
							       /*							if (hs_state != 4) {
															throw new Error("Server Finished received when hs_state != 4");
															}
							       */
							       if (callbacks.hs_recv_server_finished != undefined) {
								   let send = callbacks.hs_recv_server_finished(hs_msgs, cipherState);
								   send.forEach(sendRecord);
							       }
							       hs_msgs = [];
							       hs_state = 5;
							       if (callbacks.app_data_send != undefined) {
								   let send = callbacks.app_data_send(hs_msgs, cipherState);
								   send.forEach(sendRecord);
							       }
							   }
						       }));
	    }
	}
    }
}
const tls_server = function (port:number, callbacks, close_cb:(string => void)) {
    net.createServer(function (server) {
	const cipherState = handshake.defaultCipherState();
	cipherState.role = "server";
	let record_buf = "";
	let hs_buf = "";
	let hs_state = 0;
	let hs_msgs = [];
	server.setEncoding('hex');

	function sendRecord(msg, cp) {
	    server.write(outputRecord(cp, msg, true), 'hex')
	}

	function deliver(msg) {
	    if (cipherState.require_alert && msg.type != formats.ContentType.alert) {
		console.log("Alert expected, but non-alert received.");
		return;
	    }
	    if (msg.type === formats.ContentType.alert) {
		if (cipherState.require_alert) {
		    console.log("Alert expected and received.");
		}
		if (cipherState.expect_early_data &&
		    msg.fragment == formats.AD.end_of_early_data &&
		    callbacks.end_of_early_data_recv != undefined) {
		    callbacks.end_of_early_data_recv(cipherState);
		}
		if (msg.fragment.startsWith("02")) {
		    console.log("Fatal alert: closing connection");
		    server.end();
		}
	    } else if (msg.type === formats.ContentType.change_cipher_spec) {
		if (hs_state != 1) {
		    throw new Error("Server CCS received when hs_state != 1");
		}
		if (callbacks.hs_recv_client_ccs != undefined) {
		    let send = callbacks.hs_recv_client_ccs(hs_msgs, cipherState);
		    send.forEach(function (v) {
			sendRecord(v, cipherState)
		    });
		}
		cipherState.read = true;
		hs_msgs = [];
		hs_state = 2;
	    } else if (msg.type === formats.ContentType.application_data) {
		if (hs_state != 3) {
		    throw new Error("App Data received when hs_state != 3");
		}
		//console.log("App Data Recd: "+(hs_msg.fragment));
		if (cipherState.read == false) {
		    throw new Error("Unexpected app data, aborting");
		}
		const ad = msg;
		if (cipherState.expect_early_data) {

		} else if (callbacks.app_data_recv != undefined) {
		    let send = callbacks.app_data_recv(ad.fragment, cipherState);
		    send.forEach(function (v) {
			sendRecord(v, cipherState);
		    });
		};
		//if (close_cb) {close_cb();}
	    } else if (msg.type === formats.ContentType.handshake) {
		let hsm = msg;
		hs_buf += hsm.fragment;
		let more = false;
		do {
		    let msg = formats.parseMessage(hs_buf);
	            switch (msg.result) {
		    case "Error": 
			more = false
			return false
		    case "Correct":
			if (msg.value.fst == null) {
			    more = true;
			    return false;}
			else {
   			    let nm:hs_msg = msg.value.fst;

			    hs_buf = msg.value.snd;
			    mapError(formats.parseHandshakeMessage(nm, cipherState.params.pv,
								   cipherState.params.kex,false),
				     (m => {
					 nm.pl = m;
					 hs_msgs.push(nm);
					 if (nm.ht === formats.HT.client_hello) {
					     if (hs_state != 0) {
						 throw new Error("Client Hello received when hs_state != 0")
					     }
					     if (typeof (callbacks.hs_recv_client_hello) !== 'undefined') {
						 let send = callbacks.hs_recv_client_hello(hs_msgs, cipherState);
						 send.forEach(function (v) {
						     sendRecord(v, cipherState);
						 });
					     }
					     hs_msgs = [];
					     hs_state = 1;
					     if (cipherState.params.pv != formats.PV.TLS_1p3 && typeof (callbacks.hs_send_server_hello_done) !== 'undefined') {
						 
						 let send = callbacks.hs_send_server_hello_done(hs_msgs, cipherState);
						 send.forEach(function (v) {
						     sendRecord(v, cipherState)
						 });
					     } else if (cipherState.params.pv == formats.PV.TLS_1p3 && typeof (callbacks.hs_send_server_finished) !== 'undefined') {
						 
						 let send = callbacks.hs_send_server_finished(hs_msgs, cipherState);
						 send.forEach(function (v) {
						     sendRecord(v, cipherState)
						 });
					     }
					 } else if (nm.ht === formats.HT.finished) {
					     /*
					       if (hs_state != 2) {
					       throw new Error("Client Finished received when hs_state != 2");
					       }
                                             */
					     if (callbacks.hs_recv_client_finished0 != undefined && cipherState.expect_early_data) {
						 let send = callbacks.hs_recv_client_finished0(hs_msgs,
											       cipherState);
						 send.forEach(function (v) {
						     sendRecord(v, cipherState);
						 });
					     } else if (callbacks.hs_recv_client_finished != undefined) {
						 let send = callbacks.hs_recv_client_finished(hs_msgs,
											      cipherState);
						 send.forEach(function (v) {
						     sendRecord(v, cipherState);
						 });
					     }
					     hs_msgs = [];
					     hs_state = 3;
					 }
				     }))};
			}
		    } while (more);
	    }
	}
	server.on('data', function (data) {
	    record_buf += data;
	    let more = false;
	    do {
		const sp = formats.splitRecord(record_buf);
		switch (sp.result) {
		case "Correct":
		    record_buf = sp.value.snd;
		    deliver(inputRecord(cipherState, sp.value.fst, false));
		    more = true;
		    break;
		case "Error":
		    more = false;
		    break;
		default:
		    break;
		}
	    } while (more);
	});
	server.on('close', function () {
	    console.log('Connection closed');
	});
    }).listen(port)
}
module.exports = {
    TLS_client_scenario: TLS_client_scenario,
    TLS_server_scenario: TLS_server_scenario,
    tls_server: tls_server,
    tls_client: tls_client,
    logRecord: logRecord
}
