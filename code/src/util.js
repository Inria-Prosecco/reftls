/* @flow weak */

	const empty_bytes = ""
        const pad = function (l:number) {
		var v = "";
		var i = 0;
		for (i = 0; i <= l; i++) {
			v += bytes_of_int(l % 256, 1);
		}
		return v;
	}
	const mem = function (v, a) {
		return (a.indexOf(v) !== -1)
	}
	const hex2a = function (hex) {
		var str = '';
		for (var i = 0; i < hex.length; i += 2) str += String.fromCharCode(
			parseInt(hex.substr(i, 2), 16));
		return str;
	}
	const hexStringToByteArray = function (b) {
	    var a = [];
	    var c = 0;
	    for (var i = 0; i < b.length; i += 2) {
		a[c] = parseInt(b[i] + b[i + 1], 16)
		c++
	    }
	    return a;
	}
	const byteArrayToHexString = function (a) {
		var b = ''
		var x = ''
		for (var i = 0; i < a.length; i++) {
			x = a[i].toString(16)
			if (x.length === 1) {
				b += '0'
			}
			b += x
		}
		return b
	}
	const a2hex = function (a) {
		var str = '';
		for (var i = 0; i < a.length; i++) str += a.charCodeAt(i).toString(16);
		return str;
	}
	const substr = function (s, f, t) {
		return s.substr(f, t)
	}
	const repr_bytes = function (data) {
		const l = (data.length) / 2;
		if (l < 256) return 1;
		else if (l < 65536) return 2;
		else if (l < 16777216) return 3;
		else return 4
	}
    const zeroes = function (l:number) {
		var v = "";
		for (var i = 0; i < l; i++) v += "0";
		return v;
	}
	const bytes_of_int = function (n, l) {
		const nb = n.toString(16);
		const nl = nb.length;
		const l2 = 2 * l;
		if (nl > l2) throw ("bytes_of_int given too short a length" + (new Error()).stack);
		else if (nl < l2) return zeroes(l2 - nl) + nb;
		else return nb
	}
	const int_of_bytes = function (nb, l) {
		if (getLength(nb) != l) throw ("int_of_bytes given incorrect length" + (new Error())
			.stack);
		else return parseInt(nb, 16);
	}

        const split = function (data, n) : pair<string,string>{
		const n2 = 2 * n;
		return ({
			fst: data.slice(0, n2),
			snd: data.slice(n2)
		})
	}
	const getLength = function (d) {
		if (d.length % 2 == 0) return d.length / 2;
		else throw ("Length must be given even-length string, given d.length:" + d
			.length + ",d.substr(0,10):" + d.substring(0, 10) + (new Error()).stack)
	}

module.exports = {
		mem: mem,
		empty_bytes: empty_bytes,
		zeroes: zeroes,
		getLength: getLength,
		pad: pad,
		split: split,
		int_of_bytes: int_of_bytes,
		bytes_of_int: bytes_of_int,
		hex2a: hex2a,
		a2hex: a2hex,
		substr: substr,
    hexStringToByteArray: hexStringToByteArray,
    byteArrayToHexString: byteArrayToHexString
	}
