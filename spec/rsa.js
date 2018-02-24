'use strict';

var Buffer = require('safe-buffer').Buffer,
	expect = require('chai').expect,
	jwa = require('jwa'),
	mocha = require('mocha');

var describe = mocha.describe,
	it = mocha.it;

var jwkToPem = require('..');

describe('rsa', function() {
	it('should convert a public JWK to a public PEM', function() {
		var jwk = {
			kty: 'RSA',
			n: '7vjaE_vNFz-FbQ4GNNh-OeY6K4qWyDIvLUfz0YlhjPKfpGSv3mrcatEbAL_vny_FdCgbg1Co_bb6t_p2B2iFdVjY5hr1bXkViPVA-77-F1Cx57ZozEBixNv1-6NbfEiA_OsaPR0kMdkI9iWhF7TokMleHF1RJ_2WR1vcRb-Z99x5LitYTZTmYkcjsZiQBs_YQOZ220WOYNywgg6Xd03ErqAkltucegb4XUkmVl9JxiHoDrXVAmRUj2stDSvE4b2XftNU86v1p8FMykaeQUUXz_8EcTPdt5SydUPtCcdspSFKbKJh4aP_Zp3Fv1iOyQOsF5WB8CO7FssKLBGElHEriQ',
			e: 'AQAB'
		};

		var expected =
			'-----BEGIN PUBLIC KEY-----\n'
			+ 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7vjaE/vNFz+FbQ4GNNh+\n'
			+ 'OeY6K4qWyDIvLUfz0YlhjPKfpGSv3mrcatEbAL/vny/FdCgbg1Co/bb6t/p2B2iF\n'
			+ 'dVjY5hr1bXkViPVA+77+F1Cx57ZozEBixNv1+6NbfEiA/OsaPR0kMdkI9iWhF7To\n'
			+ 'kMleHF1RJ/2WR1vcRb+Z99x5LitYTZTmYkcjsZiQBs/YQOZ220WOYNywgg6Xd03E\n'
			+ 'rqAkltucegb4XUkmVl9JxiHoDrXVAmRUj2stDSvE4b2XftNU86v1p8FMykaeQUUX\n'
			+ 'z/8EcTPdt5SydUPtCcdspSFKbKJh4aP/Zp3Fv1iOyQOsF5WB8CO7FssKLBGElHEr\n'
			+ 'iQIDAQAB\n'
			+ '-----END PUBLIC KEY-----\n'
		;

		expect(jwkToPem(jwk)).to.equal(expected);
	});

	it('should convert a private JWK to a public PEM', function() {
		var jwk = {
			kty: 'RSA',
			n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
			e: 'AQAB',
			d: 'X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q',
			p: '83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs',
			q: '3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk',
			dp: 'G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0',
			dq: 's9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk',
			qi: 'GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU'
		};

		var expected =
			'-----BEGIN PUBLIC KEY-----\n'
			+ 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vx7agoebGcQSuuPiLJX\n'
			+ 'ZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tS\n'
			+ 'oc/BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ/2W+5JsGY4Hc5n9yBXArwl93lqt\n'
			+ '7/RN5w6Cf0h4QyQ5v+65YGjQR0/FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0\n'
			+ 'zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt+bFTWhAI4vMQFh6WeZu0f\n'
			+ 'M4lFd2NcRwr3XPksINHaQ+G/xBniIqbw0Ls1jF44+csFCur+kEgU8awapJzKnqDK\n'
			+ 'gwIDAQAB\n'
			+ '-----END PUBLIC KEY-----\n';

		expect(jwkToPem(jwk)).to.equal(expected);
	});

	it('should convert a private JWK to a pribate PEM when private option is specified', function() {
		var jwk = {
			kty: 'RSA',
			n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
			e: 'AQAB',
			d: 'X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q',
			p: '83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs',
			q: '3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk',
			dp: 'G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0',
			dq: 's9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk',
			qi: 'GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU'
		};

		var expected =
			'-----BEGIN RSA PRIVATE KEY-----\n'
			+ 'MIIEowIBAAKCAQEA0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78L\n'
			+ 'hWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc/BJECPebWKRXjBZCiFV4n3oknj\n'
			+ 'hMstn64tZ/2W+5JsGY4Hc5n9yBXArwl93lqt7/RN5w6Cf0h4QyQ5v+65YGjQR0/F\n'
			+ 'DW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbO\n'
			+ 'pbISD08qNLyrdkt+bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ+G/xBni\n'
			+ 'Iqbw0Ls1jF44+csFCur+kEgU8awapJzKnqDKgwIDAQABAoIBAF+HE7XiWP4J+BWD\n'
			+ '7FwfK3V4seb8LINRSzeRNxGhukSaFR/hyyyg/TO3ceaKOxlEZJ3IZ60cHlJAu4U+\n'
			+ 'XySzNFmxQCjS1mNr7+wejal0s1L8U9P2En6oo8Kd0U85QWgsVqeHaBZOTdqPBsv5\n'
			+ 'xzSq6AAyJCeOqUVKIbF8sG0XgHWGjMBbPbb/Hf3D1WN4tO2t7fDDekzcJtHUmsJv\n'
			+ 'b+O1Igpd0pOWYhu8aIzy7uLG4NVNo8eCAUzQc52yUsxRyuuo0/G4JLqrJNBo7JAy\n'
			+ 'ZNfWeKsI8G7J5+I9lgYot0S/lLNpRlZGPH5Bc5ntc9B2yJH89GOpqpzmLanNF+I3\n'
			+ '3CqAAvECgYEA83i+7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxt\n'
			+ 'PVnwD20R+60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQy\n'
			+ 'qVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfsCgYEA3dfO\n'
			+ 'R9cuYq+0S+mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgT\n'
			+ 'nCdpYzBcOfW5r370AFXjiWft/NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ+1k\n'
			+ 'Yd/s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxkCgYAbiw9eRzphr3Lyglb38guP\n'
			+ 'jG6mm7SXOL8ftVORLzGPlJ1fdygTSiKZjDEiLZ6ZMC57RQ5rl2mAUbIEnhzy1DZU\n'
			+ 'XjTZdG6AoNM/xqRiEWjm0ADvtB782a25hlzcLebcjbgbYa9HmxIPFTIA3bOrwt+f\n'
			+ '0RSazqtjc5vxh6IqROIGPQKBgQCz2UAf1+CAGygVHw5pzZH8TaDDbzatPaQY4CG8\n'
			+ 'iWURMTV5+sDqG5RS8x8FwymfyWp5bq/POdhjlJJAXukx0L9qAjecbwhunUFRvQlS\n'
			+ 'KtpE2pR8uFxBv930YXgOHt7vhZtGyhtGie6NNg3XEJo/pM7rWO9atf4vXy3FfDj3\n'
			+ 'hD9yCQKBgBsjP6eia18kos9baBYCm1lfiXSN40OMqbva2zFsd60CQX5rdBaGM4FC\n'
			+ 'GRFRRHDqsHpkTfNc6AwGmvgZNCljRg4yR2Q3Q5hYVtwDe5SPqbsZP5h2Ridda8ck\n'
			+ 'fDueVy0nt0j5kXysGSOslNuGcb0ChWCLXZXVChszuiGus0yoQFUV\n'
			+ '-----END RSA PRIVATE KEY-----\n';

		expect(jwkToPem(jwk, { private: true })).to.equal(expected);
	});

	it('should round-trip sign/verify with public and private keys', function() {
		var jwk = {
			kty: 'RSA',
			n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
			e: 'AQAB',
			d: 'X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q',
			p: '83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs',
			q: '3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk',
			dp: 'G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0',
			dq: 's9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk',
			qi: 'GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU'
		};

		var priv = jwkToPem(jwk, { private: true }),
			pub = jwkToPem(jwk);

		var alg = jwa('rs256'),
			input = Buffer.from('stuff n\' things', 'utf8');

		expect(alg.verify(input, alg.sign(input, priv), pub)).to.be.true;
	});

	describe('should throw for', function() {
		it('missing n', function() {
			var jwk = { kty: 'RSA', e: 'AQAB' };

			function fn() {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(TypeError);
		});

		it('non-string n', function() {
			var jwk = { kty: 'RSA', n: {}, e: 'AQAB' };

			function fn() {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(TypeError);
		});

		it('missing e', function() {
			var jwk = { kty: 'RSA', n: 'foo' };

			function fn() {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(TypeError);
		});

		it('non-string e', function() {
			var jwk = { kty: 'RSA', n: 'foo', e: {} };

			function fn() {
				return jwkToPem(jwk);
			}

			expect(fn).to.throw(TypeError);
		});

		it('missing d when private', function() {
			var jwk = { kty: 'RSA', n: 'a', e: 'b', p: 'd', q: 'e', dp: 'f', dq: 'g', qi: 'h' };

			function fn() {
				return jwkToPem(jwk, { private: true });
			}

			expect(fn).to.throw(TypeError);
		});

		it('non-string d when private', function() {
			var jwk = { kty: 'RSA', n: 'a', e: 'b', d: {}, p: 'd', q: 'e', dp: 'f', dq: 'g', qi: 'h' };

			function fn() {
				return jwkToPem(jwk, { private: true });
			}

			expect(fn).to.throw(TypeError);
		});

		it('missing p when private', function() {
			var jwk = { kty: 'RSA', n: 'a', e: 'b', d: 'c', q: 'e', dp: 'f', dq: 'g', qi: 'h' };

			function fn() {
				return jwkToPem(jwk, { private: true });
			}

			expect(fn).to.throw(TypeError);
		});

		it('non-string p when private', function() {
			var jwk = { kty: 'RSA', n: 'a', e: 'b', d: 'c', p: {}, q: 'e', dp: 'f', dq: 'g', qi: 'h' };

			function fn() {
				return jwkToPem(jwk, { private: true });
			}

			expect(fn).to.throw(TypeError);
		});

		it('missing q when private', function() {
			var jwk = { kty: 'RSA', n: 'a', e: 'b', d: 'c', p: 'd', dp: 'f', dq: 'g', qi: 'h' };

			function fn() {
				return jwkToPem(jwk, { private: true });
			}

			expect(fn).to.throw(TypeError);
		});

		it('non-string q when private', function() {
			var jwk = { kty: 'RSA', n: 'a', e: 'b', d: 'c', p: 'd', q: {}, dp: 'f', dq: 'g', qi: 'h' };

			function fn() {
				return jwkToPem(jwk, { private: true });
			}

			expect(fn).to.throw(TypeError);
		});

		it('missing dp when private', function() {
			var jwk = { kty: 'RSA', n: 'a', e: 'b', d: 'c', p: 'd', q: 'e', dq: 'g', qi: 'h' };

			function fn() {
				return jwkToPem(jwk, { private: true });
			}

			expect(fn).to.throw(TypeError);
		});

		it('non-string dp when private', function() {
			var jwk = { kty: 'RSA', n: 'a', e: 'b', d: 'c', p: 'd', q: 'e', dp: {}, dq: 'g', qi: 'h' };

			function fn() {
				return jwkToPem(jwk, { private: true });
			}

			expect(fn).to.throw(TypeError);
		});

		it('missing dq when private', function() {
			var jwk = { kty: 'RSA', n: 'a', e: 'b', d: 'c', p: 'd', q: 'e', dp: 'f', qi: 'h' };

			function fn() {
				return jwkToPem(jwk, { private: true });
			}

			expect(fn).to.throw(TypeError);
		});

		it('non-string dq when private', function() {
			var jwk = { kty: 'RSA', n: 'a', e: 'b', d: 'c', p: 'd', q: 'e', dp: 'f', dq: {}, qi: 'h' };

			function fn() {
				return jwkToPem(jwk, { private: true });
			}

			expect(fn).to.throw(TypeError);
		});

		it('missing qi when private', function() {
			var jwk = { kty: 'RSA', n: 'a', e: 'b', d: 'c', p: 'd', q: 'e', dp: 'f', dq: 'g' };

			function fn() {
				return jwkToPem(jwk, { private: true });
			}

			expect(fn).to.throw(TypeError);
		});

		it('non-string qi when private', function() {
			var jwk = { kty: 'RSA', n: 'a', e: 'b', d: 'c', p: 'd', q: 'e', dp: 'f', dq: 'g', qi: {} };

			function fn() {
				return jwkToPem(jwk, { private: true });
			}

			expect(fn).to.throw(TypeError);
		});
	});
});
