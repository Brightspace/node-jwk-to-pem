'use strict';

var asn1 = require('asn1.js'),
	BN = asn1.bignum,
	curves = require('./ec-curves'),
	rfc3280 = require('asn1.js-rfc3280');

function jwkParamToBigNum (val) {
	val = new Buffer(val, 'base64');
	val = new BN(val, 10, 'be').iabs();
	return val;
}

function ecJwkToBuffer (jwk) {
	if ('string' !== typeof jwk.crv) {
		throw new TypeError('Expected "jwk.crv" to be a String');
	}

	if ('string' !== typeof jwk.x) {
		throw new TypeError('Expected "jwk.x" to be a String');
	}

	if ('string' !== typeof jwk.y) {
		throw new TypeError('Expected "jwk.y" to be a String');
	}

	var curve = curves[jwk.crv];
	if (!curve) {
		throw new Error('Unsupported curve "' + jwk.crv + '"');
	}

	var x = jwkParamToBigNum(jwk.x),
		y = jwkParamToBigNum(jwk.y);

	var key = curve.keyFromPublic({ x: x, y: y });

	var result = keyToPem(jwk.crv, key);

	return result;
}

function keyToPem (crv, key) {
	var oid;
	switch (crv) {
		case 'P-256': {
			oid = [1, 2, 840, 10045, 3, 1, 7];
			break;
		}
		case 'P-384': {
			oid = [1, 3, 132, 0, 34];
			break;
		}
		case 'P-521': {
			oid = [1, 3, 132, 0, 35];
			break;
		}
		default: {
			throw new Error('Unsupported curve "' + crv + '"');
		}
	}

	var compact = false;
	var subjectPublicKey = key.getPublic(compact, 'hex');
	subjectPublicKey = new Buffer(subjectPublicKey, 'hex');

	var result = rfc3280.SubjectPublicKeyInfo.encode({
		algorithm: {
			algorithm: [1, 2, 840, 10045, 2, 1],
			parameters: ECParameters.encode({
				type: 'namedCurve',
				value: oid
			}, 'der')
		},
		subjectPublicKey: {
			unused: 0,
			data: subjectPublicKey
		}
	}, 'der');

	result = result.toString('base64');
	result = guardDer(result);

	return result;
}

function guardDer (der) {
	var openGuard = '-----BEGIN PUBLIC KEY-----\n',
			endGuard = '-----END PUBLIC KEY-----\n';

	der = der.match(/.{1,64}/g).join('\n') + '\n';

	var result = openGuard + der + endGuard;

	return result;
}

var ECParameters = asn1.define('ECParameters', function () {
	this.choice({
		namedCurve: this.objid()
	});
});

module.exports = ecJwkToBuffer;
