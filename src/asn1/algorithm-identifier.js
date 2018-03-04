'use strict';

module.exports = require('asn1.js').define('AlgorithmIdentifer', /* @this */ function() {
	this.seq().obj(
		this.key('algorithm').objid(),
		this.key('parameters').optional().any()
	);
});
