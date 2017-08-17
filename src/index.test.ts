// https://bshaffer.github.io/oauth2-server-php-docs/grant-types/authorization-code/
// https://tools.ietf.org/html/rfc6749

import { expect } from 'chai';
import 'co-mocha';
import 'mocha';

import { OAuth2Framework } from './index';
import { Client } from './models/client';

describe('Tests', () => {

    let framework: OAuth2Framework = null;

    describe('authorizationRequest', () => {
        it('should throw error given invalid response_type', function* () {
            framework = new OAuth2Framework({
                findClient: null,
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: null,
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
                    return Promise.resolve(new Client(null, null, null, null, ['redirect_uri1'], null, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: (client_id: string, username: string, password: string) => {
                    return Promise.resolve(false);
                },
            });

            const code: string = yield framework.authorizationRequest('code', 'client_id1', 'redirect_uri1', ['scope1', 'scope2'], 'state', 'username1', 'password1');

            expect(code).to.be.null;
        });

        it('should throw error given invalid client_id', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(null);
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: null,
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
                    return Promise.resolve(new Client(null, null, null, null, ['redirect_uri1'], null, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: null,
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
                    return Promise.resolve(new Client(null, null, null, null, ['redirect_uri1'], null, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: (client_id: string, username: string, password: string) => {
                    return Promise.resolve(true);
                },
            });

            const code: string = yield framework.authorizationRequest('code', 'client_id1', 'redirect_uri1', ['scope1', 'scope2'], 'state', 'username1', 'password1');

            expect(code).to.be.not.null;
        });

        it('Implicit Grant: should return access_token', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, null, ['redirect_uri1'], null, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: (client_id: string, username: string, password: string) => {
                    return Promise.resolve(true);
                },
            });

            const accessToken: string = yield framework.authorizationRequest('token', 'client_id1', 'redirect_uri1', ['scope1', 'scope2'], 'state', 'username1', 'password1');

            expect(accessToken).to.be.not.null;
        });
    });

    describe('accessTokenRequest', () => {
        it('should throw error given invalid grant_type', function* () {
            framework = new OAuth2Framework({
                findClient: null,
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: null,
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
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: null,
            });

            try {
                yield framework.accessTokenRequest('authorization_code', 'code1', 'redirect_uri1', 'invalid client_id', 'client_secret1', null, null, null);
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid client_id');
            }
        });

        it('should throw error given invalid redirect_uri', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, null, ['redirect_uri1'], null, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: null,
            });

            try {
                yield framework.accessTokenRequest('authorization_code', 'code1', 'invalid redirect_uri', 'client_id1', 'client_secret1', null, null, null);
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid redirect_uri');
            }
        });

        it('Authorization Code Grant: should throw error given invalid code', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, null, ['redirect_uri1'], null, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: null,
            });

            try {
                yield framework.accessTokenRequest('authorization_code', 'invalid code', 'redirect_uri1', 'client_id1', 'client_secret1', null, null, null);
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid code');
            }
        });

        it('Authorization Code Grant: should throw error given valid access token instead of valid code', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, null, ['redirect_uri1'], null, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: (client_id: string, username: string, password: string) => {
                    return Promise.resolve(true);
                },
            });

            try {
                const accessToken: string = yield framework.accessTokenRequest('password', 'code1', 'redirect_uri1', 'client_id1', 'client_secret1', 'username1', 'password1', []);
                yield framework.accessTokenRequest('authorization_code', accessToken, 'redirect_uri1', 'client_id1', 'client_secret1', null, null, null);
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid code');
            }
        });

        it('Authorization Code Grant: should throw error given invalid client_secret', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, null, ['redirect_uri1'], null, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: (client_id: string, username: string, password: string) => {
                    return Promise.resolve(true);
                },
            });

            try {
                const code: string = yield framework.authorizationRequest('code', 'client_id1', 'redirect_uri1', ['scope1', 'scope2'], 'state', 'username1', 'password1');
                yield framework.accessTokenRequest('authorization_code', code, 'redirect_uri1', 'client_id1', 'invalid client_secret', null, null, null);
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid client_secret');
            }
        });

        it('Authorization Code Grant: should return access token', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, 'client_secret1', null, ['redirect_uri1'], null, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: (client_id: string, username: string, password: string) => {
                    return Promise.resolve(true);
                },
            });

            const code: string = yield framework.authorizationRequest('code', 'client_id1', 'redirect_uri1', ['scope1', 'scope2'], 'state', 'username1', 'password1');

            const accessToken: string = yield framework.accessTokenRequest('authorization_code', code, 'redirect_uri1', 'client_id1', 'client_secret1', null, null, null);

            expect(accessToken).to.be.not.null;
        });

        it('Resource Owner Password Credentials Grant: should return null given invalid credentials', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, null, ['redirect_uri1'], null, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: (client_id: string, username: string, password: string) => {
                    return Promise.resolve(false);
                },
            });

            const accessToken: string = yield framework.accessTokenRequest('password', 'code1', 'redirect_uri1', 'client_id1', 'client_secret1', 'username1', 'password1', []);

            expect(accessToken).to.be.null;
        });

        it('Resource Owner Password Credentials Grant: should return access token given valid credentials', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, null, ['redirect_uri1'], null, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: (client_id: string, username: string, password: string) => {
                    return Promise.resolve(true);
                },
            });

            const accessToken: string = yield framework.accessTokenRequest('password', 'code1', 'redirect_uri1', 'client_id1', 'client_secret1', 'username1', 'password1', []);

            expect(accessToken).to.be.not.null;
        });
    });

    describe('validateAccessToken', () => {
        it('should return false given invalid token', function* () {
            framework = new OAuth2Framework({
                findClient: null,
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: null,
            });

            const result = yield framework.validateAccessToken('invalid token');
            expect(result).to.be.false;
        });

        it('should return false given code', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, 'client_secret1', null, ['redirect_uri1'], null, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: (client_id: string, username: string, password: string) => {
                    return Promise.resolve(true);
                },
            });

            const code: string = yield framework.authorizationRequest('code', 'client_id1', 'redirect_uri1', ['scope1', 'scope2'], 'state', 'username1', 'password1');

            const result = yield framework.validateAccessToken(code);
            expect(result).to.be.false;
        });

        it('should return true given valid token', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, null, ['redirect_uri1'], null, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: (client_id: string, username: string, password: string) => {
                    return Promise.resolve(true);
                },
            });

            const accessToken: string = yield framework.accessTokenRequest('password', 'code1', 'redirect_uri1', 'client_id1', 'client_secret1', 'username1', 'password1', []);

            const result = yield framework.validateAccessToken(accessToken);
            expect(result).to.be.true;
        });
    });

    describe('forgotPasswordRequest', () => {
        it('should throw error given invalid client_id', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(null);
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: null,
            });

            try {
                yield framework.forgotPasswordRequest('invalid client_id', 'username1', 'response_type1', 'redirect_uri1', '');
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid client_id');
            }
        });

        it('should throw error given client disabled forgot password', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, null, null, false, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: null,
            });

            try {
                yield framework.forgotPasswordRequest('client_id1', 'username1', 'response_type1', 'redirect_uri1', '');
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Function not enabled for client');
            }
        });

        it('should return false given sendForgotPasswordEmail fails', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, null, null, true, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: (client_id: string, username: string, resetPasswordUrl: string) => {
                    return Promise.resolve(false);
                },
                sendVerificationEmail: null,
                validateCredentials: null,
            });

            const result = yield framework.forgotPasswordRequest('client_id1', 'username1', 'response_type1', 'redirect_uri1', '');
            expect(result).to.be.false;

        });

        it('should return true given sendForgotPasswordEmail succeeds', function* () {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, null, null, true, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: (client_id: string, username: string, resetPasswordUrl: string) => {
                    return Promise.resolve(true);
                },
                sendVerificationEmail: null,
                validateCredentials: null,
            });

            const result = yield framework.forgotPasswordRequest('client_id1', 'username1', 'response_type1', 'redirect_uri1', '');
            expect(result).to.be.true;

        });

    });

});
