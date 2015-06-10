'use strict';

var expect = require('chai').expect,
	mocha = require('mocha');

var describe = mocha.describe,
	it = mocha.it;

var jwkToPem = require('..');

describe('ecdsa', function () {
	describe('P-256', function () {
		it('should convert a public JWK to a public PEM', function () {
			var jwk = {
				crv: 'P-256',
				kty: 'EC',
				x: 'gh9MmXjtmcHFesofqWZ6iuxSdAYgoPVvfJqpv1818lo',
				y: '3BDZHsNvKUb5VbyGPqcAFf4FGuPhJ2Xy215oWDw_1jc'
			};

			var expected =
				'-----BEGIN PUBLIC KEY-----\n'
				+ 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgh9MmXjtmcHFesofqWZ6iuxSdAYg\n'
				+ 'oPVvfJqpv1818lrcENkew28pRvlVvIY+pwAV/gUa4+EnZfLbXmhYPD/WNw==\n'
				+ '-----END PUBLIC KEY-----\n'
			;

			expect(jwkToPem(jwk)).to.equal(expected);
		});
	});

	describe('should throw for', function () {
		it('missing crv', function () {
			var jwk = { kty: 'EC', x: 'foo', y: 'bar' };

			function fn () {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(TypeError);
		});

		it('non-string crv', function () {
			var jwk = { kty: 'EC', crv: {}, x: 'foo', y: 'bar' };

			function fn () {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(TypeError);
		});

		it('missing x', function () {
			var jwk = { kty: 'EC', crv: 'P-256', y: 'bar' };

			function fn () {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(TypeError);
		});

		it('non-string x', function () {
			var jwk = { kty: 'EC', crv: 'P-256', x: {}, y: 'bar' };

			function fn () {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(TypeError);
		});

		it('missing y', function () {
			var jwk = { kty: 'EC', crv: 'P-256', x: 'foo' };

			function fn () {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(TypeError);
		});

		it('non-string y', function () {
			var jwk = { kty: 'EC', crv: 'P-256', x: 'foo', y: {} };

			function fn () {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(TypeError);
		});

		it('unknown curve', function () {
			var jwk = { kty: 'EC', crv: 'foozleberries', x: 'foo', y: 'bar' };

			function fn () {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(/"foozleberries"/);
		});
	});
});
