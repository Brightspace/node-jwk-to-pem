'use strict';

var asn1 = require('asn1.js');

var b64ToBn = require('./b64-to-bn');

var RSAPublicKey = asn1.define('RSAPublicKey', function () {
	this.seq().obj(
		this.key('modulus').int(),
		this.key('publicExponent').int()
	);
});

function rsaJwkToBuffer (jwk) {
	if ('string' !== typeof jwk.e) {
		throw new TypeError('Expected "jwk.e" to be a String');
	}

	if ('string' !== typeof jwk.n) {
		throw new TypeError('Expected "jwk.n" to be a String');
	}

	var pem = RSAPublicKey.encode({
		modulus: b64ToBn(jwk.n),
		publicExponent: b64ToBn(jwk.e)
	}, 'pem', {
		label: 'RSA PUBLIC KEY'
	});

	// This is in an if incase asn1.js adds a trailing \n
	if ('\n' !== pem.slice(-1)) {
		pem += '\n';
	}

	return pem;
}

module.exports = rsaJwkToBuffer;
