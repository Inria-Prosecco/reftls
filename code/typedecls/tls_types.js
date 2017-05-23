
type pair<T,U> = {
    fst:T,
    snd:U
}

type stringmap = { [key: string]: string }

type bytes = string
type bytes32 = bytes

type alert_description = bytes
type correct<T> = {
	result: "Correct",
	value: T
    }
type incorrect<T> = {
    result: "Error",
    code: alert_description,
    desc: string,
}
type result<T> = correct<T> | incorrect<T>

type protocol_version = bytes
type compression_method = bytes
type cipher_suite = bytes
type handshake_type = bytes
type extension_type = bytes
type point_format = bytes
type certificate_type = bytes

type sig_hash_alg = bytes
type supported_group = bytes
type client_hello = {
    protocol_version: protocol_version,
    client_random: bytes32,
    sessionID: bytes,
    cipher_suites: cipher_suite[],
    compressions: compression_method[],
    extensions: any
};

type server_hello = {
    protocol_version: protocol_version,
    server_random: bytes32,
    sessionID: bytes,
    cipher_suite: cipher_suite,
    compression: compression_method,
    extensions: any
};
type certificate = {
    chain: bytes[]
}

type certificate_request = {
    certificate_types: certificate_type[],
    signature_algorithms: sig_hash_alg[],
    distinguished_names: string[]
}

type signature = {
    sig_hash_alg: sig_hash_alg,
    sig_value: string
}


type server_key_exchange_ecdhe = {
    kex:"ECDHE",
    ec_params: {curve:supported_group},
    ec_public: bytes,
    sig: signature,
    sign: (cr:bytes32,sr:bytes32,pv:protocol_version) => void,
}


type server_key_exchange_dhe = {
    kex:"DHE",
    dh_params: {dh_p:bytes, dh_g:bytes},
    dh_public: bytes,
    sig: signature,
    sign: (cr:bytes32,sr:bytes32,pv:protocol_version) => void,
}

type server_key_exchange_rsa = {
    kex:"RSA",
    rsa_public: {rsa_modulus:bytes, rsa_exponent:bytes},
    sig: signature,
    sign: (cr:bytes32,sr:bytes32,pv:protocol_version) => void,
}

type server_key_exchange = server_key_exchange_ecdhe | server_key_exchange_dhe | server_key_exchange_rsa

type server_name = {
    name_type: bytes,
    host_name: bytes
}

type extension = {
    extension_type: extension_type,
    extension_data: any
}
type key_share = {
    dh_group: supported_group,
    dh_public:bytes
}

type client_key_exchange_ecdhe = {
    kex:"ECDHE",
    ec_public:bytes
}
type client_key_exchange_dhe = {
    kex:"DHE",
    dh_public:bytes
}
type client_key_exchange_rsa = {
    kex:"RSA",
    encpms:bytes
}

type client_key_exchange = client_key_exchange_ecdhe | client_key_exchange_dhe | client_key_exchange_rsa
type certificate_verify = {
    sig: signature
}
type finished = {verify_data:bytes}
type encrypted_extensions = {
    extensions: bytes
}
type new_session_ticket = {lifetime:string, ticket: bytes}

type hs_msg_type =
    client_hello | server_hello | certificate | certificate_request
    | server_key_exchange | client_key_exchange | finished | certificate_verify
    | encrypted_extensions | new_session_ticket

type hs_msg = {
    ht: handshake_type,
    pl: any,
    to_log: bytes
}

type record = {
    type:string,
    version: string,
    fragment: string
}

type key = string
type iv = string
type bytes16 = string

type config = {
    ver_min: protocol_version,
    ver_max: protocol_version,
    cipher_suites: cipher_suite[],
    groups: supported_group[],
    sigalgs: sig_hash_alg[],
    compressions: compression_method[],
}

type params = {
    host: string,
    pv: protocol_version,
    cs: cipher_suite,
    kex: string,
    ae: string,
    gn: string,
    cr: bytes,
    sr: bytes,
    gx: bytes,
    gy: bytes,
    ext_ms: boolean
}

type keys = {
    ae: string,
    writeMacKey: bytes,
    readMacKey: bytes,
    writeKey: bytes,
    readKey: bytes,
    writeIv: bytes,
    readIv: bytes,
    writeSn: number,
    readSn: number
}

type cached_session = {
    params: params,
    cert: bytes[],
    ticket: bytes,
}

type sessions = {
    params: params,
    cert: bytes[],
    ticket: bytes,
    rms: bytes,
    ems: bytes
}

type dh_keys = {[key:string] : {dh_private:bytes,dh_public:bytes}}

type cipher_state_old = {
    config: config,
    peer_p256r1_public:string,
    readMacKey: key,
    readKey: key,
    readIv: iv,
    readSn: number,
    session: any,
    writeMacKey: key,
    writeKey: key,
    writeIv: iv,
    writeSn: number,
    pv: protocol_version,
    kex: string,
    write: boolean,
    read: boolean,
    log: string,
    next: any,
    ae: string,
    ms: string,
    sr: string,
    cr: string,
    ch: client_hello,
    SS: string,
    sn: number,
    cs: cipher_suite,
    finkeys: any,
    ES:string
}


type cipher_state = {
    role: string,
    config: config,
    host:string,
    params: params,
    server_certificate: bytes[],
    client_certificate: bytes[],
    
    ch: client_hello,
    public_values: {p256:bytes,ff2048:bytes},

    log: string,
    log0: string,
    
    write: boolean,
    read:  boolean,
    read_keys: string,
    write_keys: string,
    
    expect_early_data: boolean,
    ticket: bytes,

    payload: string,
    path: string
}


