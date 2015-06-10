'use strict';

var expect = require('chai').expect,
	mocha = require('mocha');

var describe = mocha.describe,
	it = mocha.it;

var jwkToPem = require('..');

describe('rsa', function () {
	it('should convert a public JWK to a public PEM', function () {
		var jwk = {
			kty: 'RSA',
			n: '7vjaE_vNFz-FbQ4GNNh-OeY6K4qWyDIvLUfz0YlhjPKfpGSv3mrcatEbAL_vny_FdCgbg1Co_bb6t_p2B2iFdVjY5hr1bXkViPVA-77-F1Cx57ZozEBixNv1-6NbfEiA_OsaPR0kMdkI9iWhF7TokMleHF1RJ_2WR1vcRb-Z99x5LitYTZTmYkcjsZiQBs_YQOZ220WOYNywgg6Xd03ErqAkltucegb4XUkmVl9JxiHoDrXVAmRUj2stDSvE4b2XftNU86v1p8FMykaeQUUXz_8EcTPdt5SydUPtCcdspSFKbKJh4aP_Zp3Fv1iOyQOsF5WB8CO7FssKLBGElHEriQ',
			e: 'AQAB'
		};

		var expected =
			'-----BEGIN RSA PUBLIC KEY-----\n'
			+ 'MIIBCgKCAQEA7vjaE/vNFz+FbQ4GNNh+OeY6K4qWyDIvLUfz0YlhjPKfpGSv3mrc\n'
			+ 'atEbAL/vny/FdCgbg1Co/bb6t/p2B2iFdVjY5hr1bXkViPVA+77+F1Cx57ZozEBi\n'
			+ 'xNv1+6NbfEiA/OsaPR0kMdkI9iWhF7TokMleHF1RJ/2WR1vcRb+Z99x5LitYTZTm\n'
			+ 'YkcjsZiQBs/YQOZ220WOYNywgg6Xd03ErqAkltucegb4XUkmVl9JxiHoDrXVAmRU\n'
			+ 'j2stDSvE4b2XftNU86v1p8FMykaeQUUXz/8EcTPdt5SydUPtCcdspSFKbKJh4aP/\n'
			+ 'Zp3Fv1iOyQOsF5WB8CO7FssKLBGElHEriQIDAQAB\n'
			+ '-----END RSA PUBLIC KEY-----\n'
		;

		expect(jwkToPem(jwk)).to.equal(expected);
	});

	describe('should throw for', function () {
		it('missing n', function () {
			var jwk = { kty: 'RSA', e: 'AQAB' };

			function fn () {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(TypeError);
		});

		it('non-string n', function () {
			var jwk = { kty: 'RSA', n: {}, e: 'AQAB' };

			function fn () {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(TypeError);
		});

		it('missing e', function () {
			var jwk = { kty: 'RSA', n: 'foo' };

			function fn () {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(TypeError);
		});

		it('non-string e', function () {
			var jwk = { kty: 'RSA', n: 'foo', e: {} };

			function fn () {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(TypeError);
		});
	});
});
