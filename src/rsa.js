'use strict';

var asn1 = require('asn1.js');

var b64ToBn = require('./b64-to-bn');

var PublicKeyInfo = require('./asn1/public-key-info'),
	PrivateKeyInfo = require('./asn1/private-key-info'),
	Version = require('./asn1/version');

var RSAPrivateKey = asn1.define('RSAPrivateKey', /* @this */ function() {
	this.seq().obj(
		this.key('version').use(Version),
		this.key('modulus').int(),
		this.key('publicExponent').int(),
		this.key('privateExponent').int(),
		this.key('prime1').int(),
		this.key('prime2').int(),
		this.key('exponent1').int(),
		this.key('exponent2').int(),
		this.key('coefficient').int()
	);
});

var RSAPublicKey = asn1.define('RSAPublicKey', /* @this */ function() {
	this.seq().obj(
		this.key('modulus').int(),
		this.key('publicExponent').int()
	);
});

var algorithm = {
	algorithm: [1, 2, 840, 113549, 1, 1, 1],
	parameters: [5, 0]
};

function rsaJwkToBuffer(jwk, opts) {
	if ('string' !== typeof jwk.e) {
		throw new TypeError('Expected "jwk.e" to be a String');
	}

	if ('string' !== typeof jwk.n) {
		throw new TypeError('Expected "jwk.n" to be a String');
	}

	if (opts.private) {
		if ('string' !== typeof jwk.d) {
			throw new TypeError('Expected "jwk.d" to be a String');
		}

		if ('string' !== typeof jwk.p) {
			throw new TypeError('Expected "jwk.p" to be a String');
		}

		if ('string' !== typeof jwk.q) {
			throw new TypeError('Expected "jwk.q" to be a String');
		}

		if ('string' !== typeof jwk.dp) {
			throw new TypeError('Expected "jwk.dp" to be a String');
		}

		if ('string' !== typeof jwk.dq) {
			throw new TypeError('Expected "jwk.dq" to be a String');
		}

		if ('string' !== typeof jwk.qi) {
			throw new TypeError('Expected "jwk.qi" to be a String');
		}
	}

	var pem;
	if (opts.private) {
		pem = PrivateKeyInfo.encode({
			version: 0,
			privateKeyAlgorithm: algorithm,
			privateKey: RSAPrivateKey.encode({
				version: 0,
				modulus: b64ToBn(jwk.n, false),
				publicExponent: b64ToBn(jwk.e, false),
				privateExponent: b64ToBn(jwk.d, true),
				prime1: b64ToBn(jwk.p, true),
				prime2: b64ToBn(jwk.q, true),
				exponent1: b64ToBn(jwk.dp, true),
				exponent2: b64ToBn(jwk.dq, true),
				coefficient: b64ToBn(jwk.qi, true)
			}, 'der')
		}, 'pem', {
			label: 'PRIVATE KEY'
		});
	} else {
		pem = PublicKeyInfo.encode({
			algorithm: algorithm,
			PublicKey: {
				unused: 0,
				data: RSAPublicKey.encode({
					modulus: b64ToBn(jwk.n, false),
					publicExponent: b64ToBn(jwk.e, false)
				}, 'der')
			}
		}, 'pem', {
			label: 'PUBLIC KEY'
		});
	}

	// This is in an if incase asn1.js adds a trailing \n
	// istanbul ignore else
	if ('\n' !== pem.slice(-1)) {
		pem += '\n';
	}

	return pem;
}

module.exports = rsaJwkToBuffer;
