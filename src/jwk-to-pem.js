'use strict';

var ec = require('./ec'),
	rsa = require('./rsa');

/**
 *
 * @param {{kty:'EC', crv:string, d:string, x?:string, y?:string} | {kty:'EC', crv:string, x:string, y:string} | {kty:'RSA', e:string, n:string, d?:string, p?:string, q?:string, dp?:string, dq?:string, qi?:string}} jwk
 * @param {{private:boolean}=} opts
 * @returns {string}
 */
function jwkToBuffer(jwk, opts) {
	if ('object' !== typeof jwk || null === jwk) {
		throw new TypeError('Expected "jwk" to be an Object');
	}

	var kty = jwk.kty;
	if ('string' !== typeof kty) {
		throw new TypeError('Expected "jwk.kty" to be a String');
	}

	opts = opts || {};
	opts.private = opts.private === true;

	switch (kty) {
		case 'EC': {
			return ec(jwk, opts);
		}
		case 'RSA': {
			return rsa(jwk, opts);
		}
		default: {
			throw new Error('Unsupported key type "' + kty + '"');
		}
	}
}

module.exports = jwkToBuffer;
