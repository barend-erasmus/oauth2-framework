// https://bshaffer.github.io/oauth2-server-php-docs/grant-types/authorization-code/
// https://tools.ietf.org/html/rfc6749
import { expect } from 'chai';
import * as express from 'express';
import 'mocha';
import * as sinon from 'sinon';

import { OAuth2Framework } from './index';
import { Client } from './models/client';
import { Token } from './models/token';

describe('Tests', () => {
    let framework: OAuth2Framework = null;

    let client: Client = null;

    beforeEach(async () => {
        client = new Client('client', 'client_id', 'client_secret', ['email'], ['http://example.com'], true, true);

        framework = new OAuth2Framework({
            findClient: (client_id: string, request: express.Request): Promise<Client> => Promise.resolve(client),
            generateAccessToken: (client_id: string, username: string, scopes: string[], request: express.Request): Promise<string> => Promise.resolve(null),
            generateCode: (client_id: string, username: string, scopes: string[], request: express.Request): Promise<string> => Promise.resolve(null),
            register: (client_id: string, emailAddress: string, username: string, password: string, request: express.Request): Promise<boolean> => Promise.resolve(null),
            resetPassword: (client_id: string, username: string, password: string, request: express.Request): Promise<boolean> => Promise.resolve(null),
            sendForgotPasswordEmail: (client_id: string, username: string, resetPasswordUrl: string, request: express.Request): Promise<boolean> => Promise.resolve(null),
            sendVerificationEmail: (client_id: string, emailAddress: string, username: string, verificationUrl: string, request: express.Request): Promise<boolean> => Promise.resolve(null),
            validateAccessToken: (access_token: string, request: express.Request): Promise<Token> => Promise.resolve(null),
            validateCode: (code: string, request: express.Request): Promise<Token> => Promise.resolve(null),
            validateCredentials: (client_id: string, username: string, password: string, request: express.Request): Promise<boolean> => Promise.resolve(null),
            verify: (client_id: string, username: string, request: express.Request): Promise<boolean> => Promise.resolve(null),
        }, '1234567890');
    });

    afterEach(async () => {
        client = null;
        framework = null;
    });

    describe('accessTokenRequest', () => {
        it('should throw error given invalid grant type', async () => {

            try {
                await framework.accessTokenRequest('invalid_grant_type', null, null, null, null, null, null, null, null);
                throw new Error('Expected Exception');
            } catch (err) {
                expect(err.code).to.be.eq('invalid_grant_type');
            }

        });

        it('should throw error given grant type of authorization code and invalid client id', async () => {

            sinon.stub(framework.model, 'findClient').returns(Promise.resolve(null));

            try {
                await framework.accessTokenRequest('authorization_code', null, null, 'invalid_client_id', null, null, null, null, null);
                throw new Error('Expected Exception');
            } catch (err) {
                expect(err.code).to.be.eq('invalid_client_id');
            }

        });

        it('should throw error given grant type of authorization code and invalid redirect uri', async () => {

            try {
                await framework.accessTokenRequest('authorization_code', null, 'invalid_redriect_uri', null, null, null, null, null, null);
                throw new Error('Expected Exception');
            } catch (err) {
                expect(err.code).to.be.eq('invalid_redirect_uri');
            }

        });

        it('should throw error given grant type of authorization code and invalid scope', async () => {

            try {
                await framework.accessTokenRequest('authorization_code', null, 'http://example.com', null, null, null, null, ['invalid_scope'], null);
                throw new Error('Expected Exception');
            } catch (err) {
                expect(err.code).to.be.eq('invalid_scopes');
            }

        });

        it('should throw error given grant type of authorization code and invalid client secret', async () => {

            try {
                await framework.accessTokenRequest('authorization_code', null, 'http://example.com', null, 'invalid_client_secret', null, null, ['email'], null);
                throw new Error('Expected Exception');
            } catch (err) {
                expect(err.code).to.be.eq('invalid_client_secret');
            }

        });
    });
});
