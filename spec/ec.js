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

	describe('P-384', function () {
		it('should convert a public JWK to a public PEM', function () {
			var jwk = {
				crv: 'P-384',
				kty: 'EC',
				x: 'QIRvRhN2MpnTQ4teO4Y_RYFaK2Qlvc2lbhC0vALwrFOy33kUihkNUvHiTaUsp2W3',
				y: 'vSA1sCKKzT4UOavStUL2WpwcCflEyDshzy3dc1IZtACUngU2xMDDMsi0gDL9jLiU'
			};

			var expected =
				'-----BEGIN PUBLIC KEY-----\n'
				+ 'MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEQIRvRhN2MpnTQ4teO4Y/RYFaK2Qlvc2l\n'
				+ 'bhC0vALwrFOy33kUihkNUvHiTaUsp2W3vSA1sCKKzT4UOavStUL2WpwcCflEyDsh\n'
				+ 'zy3dc1IZtACUngU2xMDDMsi0gDL9jLiU\n'
				+ '-----END PUBLIC KEY-----\n'
			;

			expect(jwkToPem(jwk)).to.equal(expected);
		});
	});

	describe('P-521', function () {
		it('should convert a public JWK to a public PEM', function () {
			var jwk = {
				crv: 'P-521',
				kty: 'EC',
				x: 'AFqLf9vO672gS-Lv_BabqzKoedNLQgZkCemRZuzYu4KJjHgPBZ5fs3S05MoRXl4e7lR026XDDNPXawySVDXta9KF',
				y: 'APbUNzQ7IP_Mi0XwLN_RWZcIyHI43MJIAEn7O-KS0r8lvxjnVXeoopWAdqfTX_fCHXpYN1Ux1soOWujXb1uCEb7G'
			};

			var expected =
				'-----BEGIN PUBLIC KEY-----\n'
				+ 'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAWot/287rvaBL4u/8FpurMqh500tC\n'
				+ 'BmQJ6ZFm7Ni7gomMeA8Fnl+zdLTkyhFeXh7uVHTbpcMM09drDJJUNe1r0oUA9tQ3\n'
				+ 'NDsg/8yLRfAs39FZlwjIcjjcwkgASfs74pLSvyW/GOdVd6iilYB2p9Nf98Idelg3\n'
				+ 'VTHWyg5a6NdvW4IRvsY=\n'
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

		it('point not on curve', function () {
			var jwk = { kty: 'EC', crv: 'P-256', x: 'gh9MmX', y: '3BDZHsNv' };

			function fn () {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(/Invalid key for curve:/);
		});
	});
});
