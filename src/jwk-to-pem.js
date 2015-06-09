'use strict';

var ec = require('./ec'),
	rsa = require('./rsa');

function jwkToBuffer (jwk) {
	if ('object' !== typeof jwk || null === jwk) {
		throw new Error('Expected "jwk" to be an Object');
	}

	var kty = jwk.kty;
	if ('string' !== typeof kty) {
		throw new Error('Expected "jwk.kty" to be a String');
	}

	switch (kty) {
		case 'EC': {
			return ec(jwk);
		}
		case 'RSA': {
			return rsa(jwk);
		}
		default: {
			throw new Error('Unsupported key type "' + kty + '"');
		}
	}
}

module.exports = jwkToBuffer;
