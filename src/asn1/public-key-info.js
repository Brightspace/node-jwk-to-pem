'use strict';

var AlgorithmIdentifier = require('./algorithm-identifier');

module.exports = require('asn1.js').define('PublicKeyInfo', /* @this */ function() {
	this.seq().obj(
		this.key('algorithm').use(AlgorithmIdentifier),
		this.key('PublicKey').bitstr()
	);
});
