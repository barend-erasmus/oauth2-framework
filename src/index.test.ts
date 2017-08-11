// https://bshaffer.github.io/oauth2-server-php-docs/grant-types/authorization-code/
// https://tools.ietf.org/html/rfc6749

import { expect } from 'chai';
import 'mocha';
import 'co-mocha';

import { OAuth2Framework } from './index';
import { Client } from './models/client';

describe('Tests', () => {

    let framework: OAuth2Framework = null;

    beforeEach(() => {

    });

    describe('authorizationRequest', () => {
        it('should throw error given invalid response_type', function* () {
            framework = new OAuth2Framework({
                findClient: null,
                validateCredentials: null
            });

            try {
                yield framework.authorizationRequest('invalid response_type', 'client_id1', 'redirect_uri1', ['scope1', 'scope2'], 'state', 'username1', 'password1');
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid response_type');
            }
        });

        it('should return null given invalid credentials', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, ['redirect_uri1']));
                },
                validateCredentials: (client_id: string, username: string, password: string) => {
                    return Promise.resolve(false);
                }
            });

            const code: string = yield framework.authorizationRequest('code', 'client_id1', 'redirect_uri1', ['scope1', 'scope2'], 'state', 'username1', 'password1');

            expect(code).to.be.null;
        });

        it('should throw error given invalid client_id', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(null);
                },
                validateCredentials: null
            });

            try {
                yield framework.authorizationRequest('code', 'invalid client_id', 'redirect_uri1', ['scope1', 'scope2'], 'state', 'username1', 'password1');
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid client_id');
            }
        });

        it('should throw error given invalid redirect_uri', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, ['redirect_uri1']));
                },
                validateCredentials: null
            });

            try {
                yield framework.authorizationRequest('code', 'client_id1', 'invalid redirect_uri', ['scope1', 'scope2'], 'state', 'username1', 'password1');
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid redirect_uri');
            }
        });

        it('Authorization Code Grant: should return code', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, ['redirect_uri1']));
                },
                validateCredentials: (client_id: string, username: string, password: string) => {
                    return Promise.resolve(true);
                }
            });

            const code: string = yield framework.authorizationRequest('code', 'client_id1', 'redirect_uri1', ['scope1', 'scope2'], 'state', 'username1', 'password1');

            expect(code).to.be.not.null;
        });

        it('Implicit Grant: should return access_token', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, ['redirect_uri1']));
                },
                validateCredentials: (client_id: string, username: string, password: string) => {
                    return Promise.resolve(true);
                }
            });

            const accessToken: string = yield framework.authorizationRequest('token', 'client_id1', 'redirect_uri1', ['scope1', 'scope2'], 'state', 'username1', 'password1');

            expect(accessToken).to.be.not.null;
        });
    });

    describe('accessTokenRequest', () => {
        it('should throw error given invalid grant_type', function* () {
            framework = new OAuth2Framework({
                findClient: null,
                validateCredentials: null
            });

            try {
                yield framework.accessTokenRequest('invalid grant_type', 'code1', 'redirect_uri1', 'client_id1', 'client_secret1', null, null, null);
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid grant_type');
            }
        });

        it('should throw error given invalid client_id', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(null);
                },
                validateCredentials: null
            });

            try {
                yield framework.accessTokenRequest('authorization_code', 'code1', 'redirect_uri1', 'invalid client_id', 'client_secret1', null, null, null);
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid client_id');
            }
        });

        it('Authorization Code Grant: should throw error given invalid code', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, null));
                },
                validateCredentials: null
            });

            try {
                yield framework.accessTokenRequest('authorization_code', 'invalid code', 'redirect_uri1', 'client_id1', 'client_secret1', null, null, null);
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid code');
            }
        });

        it('Authorization Code Grant: should return access token', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, ['redirect_uri1']));
                },
                validateCredentials: (client_id: string, username: string, password: string) => {
                    return Promise.resolve(true);
                }
            });

            const code: string = yield framework.authorizationRequest('code', 'client_id1', 'redirect_uri1', ['scope1', 'scope2'], 'state', 'username1', 'password1');

            const accessToken: string = yield framework.accessTokenRequest('authorization_code', code, 'redirect_uri1', 'client_id1', 'client_secret1', null, null, null);

            expect(accessToken).to.be.not.null;
        });

        it('Resource Owner Password Credentials Grant: should return null given invalid credentials', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, null));
                },
                validateCredentials: (client_id: string, username: string, password: string) => {
                    return Promise.resolve(false);
                }
            });

            const accessToken: string = yield framework.accessTokenRequest('password', 'code1', 'redirect_uri1', 'client_id1', 'client_secret1', 'username1', 'password1', []);

            expect(accessToken).to.be.null;
        });

        it('Resource Owner Password Credentials Grant: should return access token given valid credentials', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, null));
                },
                validateCredentials: (client_id: string, username: string, password: string) => {
                    return Promise.resolve(true);
                }
            });

            const accessToken: string = yield framework.accessTokenRequest('password', 'code1', 'redirect_uri1', 'client_id1', 'client_secret1', 'username1', 'password1', []);

            expect(accessToken).to.be.not.null;
        });
    });
});