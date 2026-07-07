'use strict';

/* global BigInt */

var asn1 = require('asn1.js'),
	Buffer = require('safe-buffer').Buffer,
	{ p256, p384, p521 } = require('@noble/curves/nist.js'),
	{ bytesToHex, hexToBytes } = require('@noble/curves/utils.js');

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
	'P-256': p256,
	'P-384': p384,
	'P-521': p521
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

	var publicKeyPoint;
	var privateKeyBytes;

	var hasPub = jwk.x && jwk.y;
	if (hasPub) {
		var xBn = b64ToBn(jwk.x, false);
		var yBn = b64ToBn(jwk.y, false);

		var xBigInt = BigInt('0x' + xBn.toString(16));
		var yBigInt = BigInt('0x' + yBn.toString(16));

		try {
			publicKeyPoint = curve.Point.fromAffine({ x: xBigInt, y: yBigInt });
			publicKeyPoint.assertValidity();
		} catch (err) {
			throw new Error('Invalid key for curve: "' + err.message + '"');
		}
	}

	if (opts.private || !hasPub) {
		var dBn = b64ToBn(jwk.d, true);
		var dHex = dBn.toString(16);

		var keyLengths = {
			'P-256': 64,
			'P-384': 96,
			'P-521': 132
		};
		var expectedLength = keyLengths[jwk.crv];
		while (dHex.length < expectedLength) {
			dHex = '0' + dHex;
		}
		privateKeyBytes = hexToBytes(dHex);

		if (!hasPub) {
			var publicKeyBytes = curve.getPublicKey(privateKeyBytes);
			publicKeyPoint = curve.Point.fromHex(bytesToHex(publicKeyBytes));
		}

		var derivedPubKey = curve.getPublicKey(privateKeyBytes);
		var derivedPoint = curve.Point.fromHex(bytesToHex(derivedPubKey));

		if (hasPub && !derivedPoint.equals(publicKeyPoint)) {
			throw new Error('Invalid key for curve: "private key does not match public key"');
		}
	}

	var result = keyToPem(jwk.crv, publicKeyPoint, privateKeyBytes, opts);

	return result;
}

function keyToPem(crv, publicKeyPoint, privateKeyBytes, opts) {
	var compact = false;
	var publicKeyHex = publicKeyPoint.toHex(compact);
	var publicKey = Buffer.from(publicKeyHex, 'hex');
	publicKey = {
		unused: 0,
		data: publicKey
	};

	var result;
	if (opts.private) {
		var privateKey = Buffer.from(privateKeyBytes);

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
