'use strict';

var getPem = require('rsa-pem-from-mod-exp');

function rsaJwkToBuffer (jwk) {
	if ('string' !== typeof jwk.e) {
		throw new TypeError('Expected "jwk.e" to be a String');
	}

	if ('string' !== typeof jwk.n) {
		throw new TypeError('Expected "jwk.n" to be a String');
	}

	var pem = getPem(jwk.n, jwk.e);

	return pem;
}

module.exports = rsaJwkToBuffer;
