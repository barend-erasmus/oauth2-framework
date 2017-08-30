// https://bshaffer.github.io/oauth2-server-php-docs/grant-types/authorization-code/
// https://tools.ietf.org/html/rfc6749

import { expect } from 'chai';
import 'mocha';

import { OAuth2Framework } from './index';
import { Client } from './models/client';

describe('Tests', () => {

    let framework: OAuth2Framework = null;

    describe('authorizationRequest', () => {
        it('should throw error given invalid response_type', async () => {
            framework = new OAuth2Framework({
                findClient: null,
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: null,
                verify: null,
            }, null);

            try {
                await framework.authorizationRequest(
                    'invalid response_type',
                    'client_id1',
                    'redirect_uri1',
                    ['scope1', 'scope2'],
                    'state',
                    'username1',
                    'password1',
                    null);
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid response_type');
            }
        });

        it('should return null given invalid credentials', async () => {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, [], ['redirect_uri1'], null, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: (client_id: string, username: string, password: string) => {
                    return Promise.resolve(false);
                },
                verify: null,
            }, null);

            const code: string = await framework.authorizationRequest(
                'code',
                'client_id1',
                'redirect_uri1',
                ['scope1', 'scope2'],
                'state',
                'username1',
                'password1',
                null);

            expect(code).to.be.null;
        });

        it('should throw error given invalid client_id', async () => {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(null);
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: null,
                verify: null,
            }, null);

            try {
                await framework.authorizationRequest(
                    'code',
                    'invalid client_id',
                    'redirect_uri1',
                    ['scope1', 'scope2'],
                    'state',
                    'username1',
                    'password1',
                    null);
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid client_id');
            }
        });

        it('should throw error given invalid redirect_uri', async () => {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, null, ['redirect_uri1'], null, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: null,
                verify: null,
            }, null);

            try {
                await framework.authorizationRequest(
                    'code',
                    'client_id1',
                    'invalid redirect_uri',
                    ['scope1', 'scope2'],
                    'state',
                    'username1',
                    'password1',
                    null);
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid redirect_uri');
            }
        });

        it('Authorization Code Grant: should return code', async () => {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, [], ['redirect_uri1'], null, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: (client_id: string, username: string, password: string) => {
                    return Promise.resolve(true);
                },
                verify: null,
            }, 'secret');

            const code: string = await framework.authorizationRequest(
                'code',
                'client_id1',
                'redirect_uri1',
                ['scope1', 'scope2'],
                'state',
                'username1',
                'password1',
                null);

            expect(code).to.be.not.null;
        });

        it('Implicit Grant: should return access_token', async () => {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, [], ['redirect_uri1'], null, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: (client_id: string, username: string, password: string) => {
                    return Promise.resolve(true);
                },
                verify: null,
            }, 'secret');

            const accessToken: string = await framework.authorizationRequest(
                'token',
                'client_id1',
                'redirect_uri1',
                ['scope1', 'scope2'],
                'state',
                'username1',
                'password1',
                null);

            expect(accessToken).to.be.not.null;
        });
    });

    describe('accessTokenRequest', () => {
        it('should throw error given invalid grant_type', async () => {
            framework = new OAuth2Framework({
                findClient: null,
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: null,
                verify: null,
            }, null);

            try {
                await framework.accessTokenRequest(
                    'invalid grant_type',
                    'code1',
                    'redirect_uri1',
                    'client_id1',
                    'client_secret1',
                    null,
                    null,
                    null,
                    null);
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid grant_type');
            }
        });

        it('should throw error given invalid client_id', async () => {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(null);
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: null,
                verify: null,
            }, null);

            try {
                await framework.accessTokenRequest(
                    'authorization_code',
                    'code1',
                    'redirect_uri1',
                    'invalid client_id',
                    'client_secret1',
                    null,
                    null,
                    null,
                    null);
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid client_id');
            }
        });

        it('should throw error given invalid redirect_uri', async () => {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, null, ['redirect_uri1'], null, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: null,
                verify: null,
            }, null);

            try {
                await framework.accessTokenRequest(
                    'authorization_code',
                    'code1',
                    'invalid redirect_uri',
                    'client_id1',
                    'client_secret1',
                    null,
                    null,
                    null,
                    null);
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid redirect_uri');
            }
        });

        it('Authorization Code Grant: should throw error given invalid code', async () => {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, null, ['redirect_uri1'], null, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: null,
                verify: null,
            }, null);

            try {
                await framework.accessTokenRequest(
                    'authorization_code',
                    'invalid code',
                    'redirect_uri1',
                    'client_id1',
                    'client_secret1',
                    null,
                    null,
                    null,
                    null);
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid code');
            }
        });

        it('Authorization Code Grant: should throw error given valid access token instead of valid code', async () => {
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
                verify: null,
            }, 'secret');

            try {
                const accessToken: string = await framework.accessTokenRequest(
                    'password',
                    'code1',
                    'redirect_uri1',
                    'client_id1',
                    'client_secret1',
                    'username1',
                    'password1',
                    [],
                    null);
                await framework.accessTokenRequest(
                    'authorization_code',
                    accessToken,
                    'redirect_uri1',
                    'client_id1',
                    'client_secret1',
                    null,
                    null,
                    null,
                    null);
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid code');
            }
        });

        it('Authorization Code Grant: should throw error given invalid client_secret', async () => {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, [], ['redirect_uri1'], null, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: (client_id: string, username: string, password: string) => {
                    return Promise.resolve(true);
                },
                verify: null,
            }, 'secret');

            try {
                const code: string = await framework.authorizationRequest(
                    'code',
                    'client_id1',
                    'redirect_uri1',
                    ['scope1', 'scope2'],
                    'state',
                    'username1',
                    'password1',
                    null);
                await framework.accessTokenRequest(
                    'authorization_code',
                    code,
                    'redirect_uri1',
                    'client_id1',
                    'invalid client_secret',
                    null,
                    null,
                    null,
                    null);
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid client_secret');
            }
        });

        it('Authorization Code Grant: should return access token', async () => {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, 'client_secret1', [], ['redirect_uri1'], null, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: (client_id: string, username: string, password: string) => {
                    return Promise.resolve(true);
                },
                verify: null,
            }, 'secret');

            const code: string = await framework.authorizationRequest(
                'code',
                'client_id1',
                'redirect_uri1',
                ['scope1', 'scope2'],
                'state',
                'username1',
                'password1',
                null);

            const accessToken: string = await framework.accessTokenRequest(
                'authorization_code',
                code,
                'redirect_uri1',
                'client_id1',
                'client_secret1',
                null,
                null,
                null,
                null);

            expect(accessToken).to.be.not.null;
        });

        it('Resource Owner Password Credentials Grant: should return null given invalid credentials', async () => {
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
                verify: null,
            }, null);

            const accessToken: string = await framework.accessTokenRequest(
                'password',
                'code1',
                'redirect_uri1',
                'client_id1',
                'client_secret1',
                'username1',
                'password1',
                [],
                null);

            expect(accessToken).to.be.null;
        });

        it('Resource Owner Password Credentials Grant: should return access token given valid credentials', async () => {
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
                verify: null,
            }, 'secret');

            const accessToken: string = await framework.accessTokenRequest(
                'password',
                'code1',
                'redirect_uri1',
                'client_id1',
                'client_secret1',
                'username1',
                'password1',
                [],
                null);

            expect(accessToken).to.be.not.null;
        });
    });

    describe('validateAccessToken', () => {
        it('should return false given invalid token', async () => {
            framework = new OAuth2Framework({
                findClient: null,
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: null,
                verify: null,
            }, null);

            const result = await framework.validateAccessToken('invalid token');
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
                verify: null,
            }, null);

            const code: string = yield framework.authorizationRequest(
                'code',
                'client_id1',
                'redirect_uri1',
                ['scope1', 'scope2'],
                'state',
                'username1',
                'password1',
                null);

            const result = yield framework.validateAccessToken(code);
            expect(result).to.be.false;
        });

        it('should return true given valid token', async () => {
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
                verify: null,
            }, 'secret');

            const accessToken: string = await framework.accessTokenRequest(
                'password',
                'code1',
                'redirect_uri1',
                'client_id1',
                'client_secret1',
                'username1',
                'password1',
                [],
                null);

            const result = await framework.validateAccessToken(accessToken);
            expect(result).to.be.true;
        });
    });

    describe('forgotPasswordRequest', () => {
        it('should throw error given invalid client_id', async () => {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(null);
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: null,
                verify: null,
            }, null);

            try {
                await framework.forgotPasswordRequest(
                    'invalid client_id',
                    'username1',
                    'response_type1',
                    'redirect_uri1',
                    '',
                    null);
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Invalid client_id');
            }
        });

        it('should throw error given client disabled forgot password', async () => {
            framework = new OAuth2Framework({
                findClient: (client_id: string) => {
                    return Promise.resolve(new Client(null, null, null, null, null, false, null));
                },
                register: null,
                resetPassword: null,
                sendForgotPasswordEmail: null,
                sendVerificationEmail: null,
                validateCredentials: null,
                verify: null,
            }, null);

            try {
                await framework.forgotPasswordRequest(
                    'client_id1',
                    'username1',
                    'response_type1',
                    'redirect_uri1',
                    '',
                    null);
                throw new Error('Expected Error');
            } catch (err) {
                expect(err.message).to.be.equal('Function not enabled for client');
            }
        });

        it('should return false given sendForgotPasswordEmail fails', async () => {
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
                verify: null,
            }, 'secret');

            const result = await framework.forgotPasswordRequest(
                'client_id1',
                'username1',
                'response_type1',
                'redirect_uri1',
                '',
                null);
            expect(result).to.be.false;

        });

        it('should return true given sendForgotPasswordEmail succeeds', async () => {
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
                verify: null,
            }, 'secret');

            const result = await framework.forgotPasswordRequest(
                'client_id1',
                'username1',
                'response_type1',
                'redirect_uri1',
                '',
                null);
            expect(result).to.be.true;

        });

    });

});
