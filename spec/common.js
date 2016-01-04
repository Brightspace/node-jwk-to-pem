'use strict';

var expect = require('chai').expect,
	mocha = require('mocha');

var describe = mocha.describe,
	it = mocha.it;

var jwkToPem = require('..');

describe('should throw for', function() {
	it('non object', function() {
		function fn() {
			return jwkToPem('hi');
		}

		expect(fn).to.throw(TypeError);
	});

	it('null', function() {
		function fn() {
			return jwkToPem(null);
		}

		expect(fn).to.throw(TypeError);
	});

	it('non string key type', function() {
		function fn() {
			return jwkToPem({ kty: {} });
		}

		expect(fn).to.throw(TypeError);
	});

	it('unknown key type', function() {
		function fn() {
			return jwkToPem({ kty: 'foozleberries' });
		}

		expect(fn).to.throw(/"foozleberries"/);
	});
});
