'use strict';

var asn1 = require('asn1.js'),
	crypto = require('crypto'),
	Buffer = require('safe-buffer').Buffer;

var b64ToBn = require('./b64-to-bn');

var PublicKeyInfo = require('./asn1/public-key-info'),
	PrivateKeyInfo = require('./asn1/private-key-info'),
	Version = require('./asn1/version');

var ECParameters = asn1.define('ECParameters', /* @this */ function() {
	this.choice({
		namedCurve: this.objid()
	});
});

var ecPrivkeyVer1 = 1;

var ECPrivateKey = asn1.define('ECPrivateKey', /* @this */ function() {
	this.seq().obj(
		this.key('version').use(Version),
		this.key('privateKey').octstr(),
		this.key('parameters').explicit(0).optional().any(),
		this.key('publicKey').explicit(1).optional().bitstr()
	);
});

var curves = {
	'P-256': { name: 'prime256v1', size: 32 },
	'P-384': { name: 'secp384r1', size: 48 },
	'P-521': { name: 'secp521r1', size: 66 }
};

var oids = {
	'P-256': [1, 2, 840, 10045, 3, 1, 7],
	'P-384': [1, 3, 132, 0, 34],
	'P-521': [1, 3, 132, 0, 35]
};
var parameters = {};
var algorithms = {};
Object.keys(oids).forEach(function(crv) {
	parameters[crv] = ECParameters.encode({
		type: 'namedCurve',
		value: oids[crv]
	}, 'der');
	algorithms[crv] = {
		algorithm:  [1, 2, 840, 10045, 2, 1],
		parameters: parameters[crv]
	};
});
oids = null;

function ecJwkToBuffer(jwk, opts) {
	if ('string' !== typeof jwk.crv) {
		throw new TypeError('Expected "jwk.crv" to be a String');
	}

	var hasD = 'string' === typeof jwk.d;
	var xyTypes = hasD
		? ['undefined', 'string']
		: ['string'];

	if (-1 === xyTypes.indexOf(typeof jwk.x)) {
		throw new TypeError('Expected "jwk.x" to be a String');
	}

	if (-1 === xyTypes.indexOf(typeof jwk.y)) {
		throw new TypeError('Expected "jwk.y" to be a String');
	}

	if (opts.private && !hasD) {
		throw new TypeError('Expected "jwk.d" to be a String');
	}

	var curve = curves[jwk.crv];
	if (!curve) {
		throw new Error('Unsupported curve "' + jwk.crv + '"');
	}

	var publicKey, privateKey;

	try {
		var hasPub = jwk.x && jwk.y;
		if (hasPub) {
			publicKey = Buffer.concat([
				Buffer.from([4]),
				b64ToFixedBuffer(jwk.x, curve.size, false),
				b64ToFixedBuffer(jwk.y, curve.size, false)
			]);

			// computeSecret rejects points that are not on the curve
			var verifier = crypto.createECDH(curve.name);
			verifier.generateKeys();
			verifier.computeSecret(publicKey);
		}

		if (opts.private || !hasPub) {
			privateKey = b64ToFixedBuffer(jwk.d, curve.size, true);

			var ecdh = crypto.createECDH(curve.name);
			ecdh.setPrivateKey(privateKey);

			if (!hasPub) {
				publicKey = ecdh.getPublicKey();
			}
		}
	} catch (e) {
		if (privateKey) {
			privateKey.fill(0);
		}
		throw new Error('Invalid key for curve: "' + e.message + '"');
	}

	return keyToPem(jwk.crv, publicKey, privateKey, opts);
}

function b64ToFixedBuffer(val, size, zero) {
	return b64ToBn(val, zero).toArrayLike(Buffer, 'be', size);
}

function keyToPem(crv, publicKey, privateKey, opts) {
	publicKey = {
		unused: 0,
		data: publicKey
	};

	var result;
	if (opts.private) {
		result = PrivateKeyInfo.encode({
			version: 0,
			privateKeyAlgorithm: algorithms[crv],
			privateKey: ECPrivateKey.encode({
				version: ecPrivkeyVer1,
				privateKey: privateKey,
				parameters: parameters[crv],
				publicKey: publicKey
			}, 'der')
		}, 'pem', {
			label: 'PRIVATE KEY'
		});

		privateKey.fill(0);
	} else {
		result = PublicKeyInfo.encode({
			algorithm: algorithms[crv],
			PublicKey: publicKey
		}, 'pem', {
			label: 'PUBLIC KEY'
		});
	}

	// This is in an if incase asn1.js adds a trailing \n
	// istanbul ignore else
	if ('\n' !== result.slice(-1)) {
		result += '\n';
	}

	return result;
}

module.exports = ecJwkToBuffer;
