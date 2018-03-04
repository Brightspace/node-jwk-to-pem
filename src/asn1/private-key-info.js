'use strict';

var AlgorithmIdentifier = require('./algorithm-identifier');
var Version = require('./version');

module.exports = require('asn1.js').define('PrivateKeyInfo', /* @this */ function() {
	this.seq().obj(
		this.key('version').use(Version),
		this.key('privateKeyAlgorithm').use(AlgorithmIdentifier),
		this.key('privateKey').octstr(),
		this.key('attributes').optional().any()
	);
});
