// https://bshaffer.github.io/oauth2-server-php-docs/grant-types/authorization-code/
// https://tools.ietf.org/html/rfc6749
import * as express from 'express';
import { expect } from 'chai';
import 'mocha';

import { OAuth2Framework } from './index';
import { Client } from './models/client';
import { Token } from './models/token';

describe('Tests', () => {
    let framework: OAuth2Framework = null;

    beforeEach(async () => {
        framework = new OAuth2Framework({
            findClient: (client_id: string, request: express.Request): Promise<Client> => Promise.resolve(null),
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

    describe('accessTokenRequest', () => {
        it('should throw error given invalid grant type', async () => {

            try {
                await framework.accessTokenRequest('invalid_grant_type', null, null, null, null, null, null, null, null);
                throw new Error('Expected Exception');
            } catch (err) {
                expect(err.code).to.be.eq('invalid_grant_type');
            }
        });
    });
});
