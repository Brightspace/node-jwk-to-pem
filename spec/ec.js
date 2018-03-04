'use strict';

var Buffer = require('safe-buffer').Buffer,
	expect = require('chai').expect,
	jwa = require('jwa'),
	mocha = require('mocha');

var describe = mocha.describe,
	it = mocha.it;

var jwkToPem = require('..');

describe('ecdsa', function() {
	describe('P-256', function() {
		it('should convert a public JWK to a public PEM', function() {
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

		it('should convert a private JWK to a public PEM', function() {
			var jwk = {
				kty: 'EC',
				crv: 'P-256',
				d: '870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE'
			};

			var expected =
				'-----BEGIN PUBLIC KEY-----\n'
				+ 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMKBCTNIcKUSDii11ySs3526iDZ8A\n'
				+ 'iTo7Tu6KPAqv7D7gS2XpJFbZiItSs3m9+9Ue6GnvHw/GW2ZZaVtszggXIw==\n'
				+ '-----END PUBLIC KEY-----\n'
			;

			expect(jwkToPem(jwk)).to.equal(expected);
		});

		it('should convert a private JWK to a private PEM when private option is specified', function() {
			var jwk = {
				kty: 'EC',
				crv: 'P-256',
				d: '870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE'
			};

			var expected =
				'-----BEGIN PRIVATE KEY-----\n'
				+ 'MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg870MB6gfuTJ4HtUn\n'
				+ 'UvYMyJpr5eUZNP4Bk43bVdj3eAGgCgYIKoZIzj0DAQehRANCAAQwoEJM0hwpRIOK\n'
				+ 'LXXJKzfnbqINnwCJOjtO7oo8Cq/sPuBLZekkVtmIi1Kzeb371R7oae8fD8ZbZllp\n'
				+ 'W2zOCBcj\n'
				+ '-----END PRIVATE KEY-----\n'
			;

			expect(jwkToPem(jwk, { private: true })).to.equal(expected);
		});

		it('should round-trip sign/verify with public and private keys', function() {
			var jwk = {
				kty: 'EC',
				crv: 'P-256',
				d: '870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE'
			};

			var priv = jwkToPem(jwk, { private: true }),
				pub = jwkToPem(jwk);

			var alg = jwa('es256'),
				input = Buffer.from('stuff n\' things', 'utf8');

			expect(alg.verify(input, alg.sign(input, priv), pub)).to.be.true;
		});
	});

	describe('P-384', function() {
		it('should convert a public JWK to a public PEM', function() {
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

		it('should convert a private JWK to a public PEM', function() {
			var jwk = {
				kty: 'EC',
				crv: 'P-384',
				d: 'pm3SR9XL7f2oHIyZoqEcC8lxNaCEzTKNHXLmP5eNBcnZgbLw680H_SAy__MtVSw3'
			};

			var expected =
				'-----BEGIN PUBLIC KEY-----\n'
				+ 'MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEYypIljLsSDoG6rfZU1eghUExWouf7U0E\n'
				+ 'GJFgla7UKRn3+UzvFXBctW3iDKqcBqcaQZKEq2EPIDExlichJbDuMVwDupEhl+hS\n'
				+ 'Srfj8mcKhy/T382XYyUTkUrIjlSf3sHf\n'
				+ '-----END PUBLIC KEY-----\n'
			;

			expect(jwkToPem(jwk)).to.equal(expected);
		});

		it('should convert a private JWK to a private PEM when private option is specified', function() {
			var jwk = {
				kty: 'EC',
				crv: 'P-384',
				d: 'pm3SR9XL7f2oHIyZoqEcC8lxNaCEzTKNHXLmP5eNBcnZgbLw680H_SAy__MtVSw3'
			};

			var expected =
				'-----BEGIN PRIVATE KEY-----\n'
				+ 'MIG/AgEAMBAGByqGSM49AgEGBSuBBAAiBIGnMIGkAgEBBDCmbdJH1cvt/agcjJmi\n'
				+ 'oRwLyXE1oITNMo0dcuY/l40FydmBsvDrzQf9IDL/8y1VLDegBwYFK4EEACKhZANi\n'
				+ 'AARjKkiWMuxIOgbqt9lTV6CFQTFai5/tTQQYkWCVrtQpGff5TO8VcFy1beIMqpwG\n'
				+ 'pxpBkoSrYQ8gMTGWJyElsO4xXAO6kSGX6FJKt+PyZwqHL9PfzZdjJRORSsiOVJ/e\n'
				+ 'wd8=\n'
				+ '-----END PRIVATE KEY-----\n'
			;

			expect(jwkToPem(jwk, { private: true })).to.equal(expected);
		});

		it('should round-trip sign/verify with public and private keys', function() {
			var jwk = {
				kty: 'EC',
				crv: 'P-384',
				d: 'pm3SR9XL7f2oHIyZoqEcC8lxNaCEzTKNHXLmP5eNBcnZgbLw680H_SAy__MtVSw3'
			};

			var priv = jwkToPem(jwk, { private: true }),
				pub = jwkToPem(jwk);

			var alg = jwa('es384'),
				input = Buffer.from('stuff n\' things', 'utf8');

			expect(alg.verify(input, alg.sign(input, priv), pub)).to.be.true;
		});
	});

	describe('P-521', function() {
		it('should convert a public JWK to a public PEM', function() {
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

		it('should convert a private JWK to a public PEM', function() {
			var jwk = {
				kty: 'EC',
				crv: 'P-521',
				d: 'AQZVlssKQF5tkcQWmQ9SP6kVwGBXzcq3Ti4fKJqDfghRWLINFO_sEomyKSzmyZUM-GUtrWmbpfnWpjAkVCQmWIg_'
			};

			var expected =
				'-----BEGIN PUBLIC KEY-----\n'
				+ 'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQADSGJ0zR4ohgDDdb81zOV4fyzs1R9\n'
				+ 'MuscyKASDtltqfScw890YoFsGRSLztCtn7IrOEMevxU3lMdiEjihzj9suAwAOFN/\n'
				+ 'qWAkZP3Ffc9Z5byx505SliPnXjavkSHkBjUM6Frt170rYsIyiQu/MuHJRLHjRDwB\n'
				+ '6sqE4xFcqiAwLKW5It8=\n'
				+ '-----END PUBLIC KEY-----\n'
			;

			expect(jwkToPem(jwk)).to.equal(expected);
		});

		it('should convert a private JWK to a private PEM when private option is specified', function() {
			var jwk = {
				kty: 'EC',
				crv: 'P-521',
				d: 'AQZVlssKQF5tkcQWmQ9SP6kVwGBXzcq3Ti4fKJqDfghRWLINFO_sEomyKSzmyZUM-GUtrWmbpfnWpjAkVCQmWIg_'
			};

			var expected =
				'-----BEGIN PRIVATE KEY-----\n'
				+ 'MIH3AgEAMBAGByqGSM49AgEGBSuBBAAjBIHfMIHcAgEBBEIBBlWWywpAXm2RxBaZ\n'
				+ 'D1I/qRXAYFfNyrdOLh8omoN+CFFYsg0U7+wSibIpLObJlQz4ZS2taZul+damMCRU\n'
				+ 'JCZYiD+gBwYFK4EEACOhgYkDgYYABAANIYnTNHiiGAMN1vzXM5Xh/LOzVH0y6xzI\n'
				+ 'oBIO2W2p9JzDz3RigWwZFIvO0K2fsis4Qx6/FTeUx2ISOKHOP2y4DAA4U3+pYCRk\n'
				+ '/cV9z1nlvLHnTlKWI+deNq+RIeQGNQzoWu3XvStiwjKJC78y4clEseNEPAHqyoTj\n'
				+ 'EVyqIDAspbki3w==\n'
				+ '-----END PRIVATE KEY-----\n'
			;

			expect(jwkToPem(jwk, { private: true })).to.equal(expected);
		});

		it('should round-trip sign/verify with public and private keys', function() {
			var jwk = {
				kty: 'EC',
				crv: 'P-521',
				d: 'AQZVlssKQF5tkcQWmQ9SP6kVwGBXzcq3Ti4fKJqDfghRWLINFO_sEomyKSzmyZUM-GUtrWmbpfnWpjAkVCQmWIg_'
			};

			var priv = jwkToPem(jwk, { private: true }),
				pub = jwkToPem(jwk);

			var alg = jwa('es512'),
				input = Buffer.from('stuff n\' things', 'utf8');

			expect(alg.verify(input, alg.sign(input, priv), pub)).to.be.true;
		});
	});

	describe('should throw for', function() {
		it('missing crv', function() {
			var jwk = { kty: 'EC', x: 'foo', y: 'bar' };

			function fn() {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(TypeError);
		});

		it('non-string crv', function() {
			var jwk = { kty: 'EC', crv: {}, x: 'foo', y: 'bar' };

			function fn() {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(TypeError);
		});

		it('missing x', function() {
			var jwk = { kty: 'EC', crv: 'P-256', y: 'bar' };

			function fn() {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(TypeError);
		});

		it('non-string x', function() {
			var jwk = { kty: 'EC', crv: 'P-256', x: {}, y: 'bar' };

			function fn() {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(TypeError);
		});

		it('missing y', function() {
			var jwk = { kty: 'EC', crv: 'P-256', x: 'foo' };

			function fn() {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(TypeError);
		});

		it('non-string y', function() {
			var jwk = { kty: 'EC', crv: 'P-256', x: 'foo', y: {} };

			function fn() {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(TypeError);
		});

		it('unknown curve', function() {
			var jwk = { kty: 'EC', crv: 'foozleberries', x: 'foo', y: 'bar' };

			function fn() {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(/"foozleberries"/);
		});

		it('point not on curve', function() {
			var jwk = { kty: 'EC', crv: 'P-256', x: 'gh9MmX', y: '3BDZHsNv' };

			function fn() {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(/Invalid key for curve:/);
		});

		it('missing d when private is enabled', function() {
			var jwk = { kty: 'EC', crv: 'P-256', x: 'gh9MmX', y: '3BDZHsNv' };

			function fn() {
				return jwkToPem(jwk, { private: true });
			}

			expect(fn).to.throw(TypeError);
		});

		it('non-string d when private is enabled', function() {
			var jwk = { kty: 'EC', crv: 'P-256', x: 'gh9MmX', y: '3BDZHsNv', d: {} };

			function fn() {
				return jwkToPem(jwk, { private: true });
			}

			expect(fn).to.throw(TypeError);
		});
	});
});
