// Imports
import * as co from 'co';
import * as jsonwebtoken from 'jsonwebtoken';

// Imports models
import { Client } from './models/client';

// Exports
export { Client } from './models/client';
export { OAuth2FrameworkRouter } from './router';

export class OAuth2Framework {

    constructor(public model: {
        findClient: (client_id: string) => Promise<Client>,
        register: (client_id: string, emailAddress: string, username: string, password: string) => Promise<boolean>,
        resetPassword: (client_id: string, username: string, password: string) => Promise<boolean>,
        sendForgotPasswordEmail: (client_id: string, username: string, resetPasswordUrl: string) => Promise<boolean>,
        sendVerificationEmail: (client_id: string, emailAddress: string, username: string, verificationUrl: string) => Promise<boolean>,
        validateCredentials: (client_id: string, username: string, password: string) => Promise<boolean>,
        verify: (client_id: string, username: string) => Promise<boolean>,
    }) {

    }

    public authorizationRequest(
        response_type: string,
        client_id: string,
        redirect_uri: string,
        scopes: string[],
        state: string,
        username: string,
        password: string): Promise<string> {

        const self = this;

        return co(function* () {

            if (response_type !== 'code' && response_type !== 'token') {
                throw new Error('Invalid response_type');
            }

            const client: Client = yield self.model.findClient(client_id);

            if (!client) {
                throw new Error('Invalid client_id');
            }

            if (client.redirectUris.indexOf(redirect_uri) === -1) {
                throw new Error('Invalid redirect_uri');
            }

            // TODO: Validate Scopes

            const validCredentials: boolean = yield self.model.validateCredentials(client_id, username, password);

            if (!validCredentials) {
                return null;
            }

            if (response_type === 'code') {
                return self.generateCode(client_id, username, scopes);
            } else if (response_type === 'token') {
                return self.generateAccessToken(client_id, username, scopes);
            }

        });
    }

    public accessTokenRequest(
        grant_type: string,
        code: string,
        redirect_uri: string,
        client_id: string,
        client_secret: string,
        username: string,
        password: string,
        scopes: string[]): Promise<string> {

        const self = this;

        return co(function* () {
            if (grant_type !== 'authorization_code' && grant_type !== 'password') {
                throw new Error('Invalid grant_type');
            }

            const client: Client = yield self.model.findClient(client_id);

            if (!client) {
                throw new Error('Invalid client_id');
            }

            if (client.redirectUris.indexOf(redirect_uri) === -1) {
                throw new Error('Invalid redirect_uri');
            }

            if (grant_type === 'password') {
                const validCredentials: boolean = yield self.model.validateCredentials(client_id, username, password);

                if (!validCredentials) {
                    return null;
                }

                return self.generateAccessToken(client_id, username, scopes);
            }

            if (grant_type === 'authorization_code') {

                const decodedCode: any = yield self.decodeJWT(code);

                if (!decodedCode) {
                    throw new Error('Invalid code');
                }

                if (decodedCode.type !== 'code') {
                    throw new Error('Invalid code');
                }

                if (client.secret !== client_secret) {
                    throw new Error('Invalid client_secret');
                }

                return self.generateAccessToken(decodedCode.client_id, decodedCode.username, decodedCode.scopes);
            }

        });
    }

    public validateAccessToken(access_token: string): Promise<boolean> {
        const self = this;

        return co(function* () {

            const decodedToken: any = yield self.decodeJWT(access_token);

            if (!decodedToken) {
                return false;
            }

            if (decodedToken.type !== 'access-token') {
                return false;
            }

            return true;
        });
    }

    public decodeResetPasswordToken(token: string): Promise<any> {
        const self = this;

        return co(function* () {

            const decodedToken: any = yield self.decodeJWT(token);

            if (!decodedToken) {
                return null;
            }

            if (decodedToken.type !== 'reset-password') {
                return null;
            }

            return decodedToken;
        });
    }

    public decodeEmailVerificationToken(token: string): Promise<any> {
        const self = this;

        return co(function* () {

            const decodedToken: any = yield self.decodeJWT(token);

            if (!decodedToken) {
                return null;
            }

            if (decodedToken.type !== 'email-verification') {
                return null;
            }

            return decodedToken;
        });
    }

    public forgotPasswordRequest(client_id: string, username: string, response_type: string, redirect_uri: string, state: string): Promise<boolean> {
        const self = this;

        return co(function* () {

            const client: Client = yield self.model.findClient(client_id);

            if (!client) {
                throw new Error('Invalid client_id');
            }

            if (!client.allowForgotPassword) {
                throw new Error('Function not enabled for client');
            }

            const returnUrl = `authorize?response_type=${response_type}&client_id=${client_id}&redirect_uri=${redirect_uri}&state=${state}`;
            const resetPasswordToken = self.generateResetPasswordToken(client_id, username, returnUrl);

            const resetPasswordUrl = `/reset-password?token=${resetPasswordToken}`;

            const result = yield self.model.sendForgotPasswordEmail(client_id, username, resetPasswordUrl);

            return result;
        });
    }

    public emailVerificationRequest(token: string): Promise<boolean> {
        const self = this;

        return co(function* () {

            const decodedToken: any = yield self.decodeEmailVerificationToken(token);

            if (!decodedToken) {
                throw new Error('Invalid token');
            }

            const client: Client = yield self.model.findClient(decodedToken.client_id);

            if (!client) {
                throw new Error('Invalid client_id');
            }

            if (!client) {
                throw new Error('Invalid client_id');
            }

            if (!client.allowRegister) {
                throw new Error('Function not enabled for client');
            }

            const result = yield self.model.verify(decodedToken.client_id, decodedToken.username);

            return result;
        });
    }

    public registerRequest(client_id: string, emailAddress: string, username: string, password: string, response_type: string, redirect_uri: string, state: string): Promise<boolean> {
        const self = this;

        return co(function* () {

            const client: Client = yield self.model.findClient(client_id);

            if (!client) {
                throw new Error('Invalid client_id');
            }

            if (!client.allowRegister) {
                throw new Error('Function not enabled for client');
            }

            const returnUrl = `authorize?response_type=${response_type}&client_id=${client_id}&redirect_uri=${redirect_uri}&state=${state}`;
            const emailVerificationToken = self.generateEmailVerificationToken(client_id, username, returnUrl);

            const emailVerificationUrl = `/email-verification?token=${emailVerificationToken}`;

            const result = yield self.model.register(client_id, emailAddress, username, password);

            if (result) {
                const emailResult = yield self.model.sendVerificationEmail(client_id, emailAddress, username, emailVerificationUrl);
            }

            return result;
        });
    }

    public resetPasswordRequest(token: string, password: string): Promise<boolean> {
        const self = this;

        return co(function* () {

            const decodedToken: any = yield self.decodeResetPasswordToken(token);

            if (!decodedToken) {
                throw new Error('Invalid token');
            }

            const client: Client = yield self.model.findClient(decodedToken.client_id);

            if (!client) {
                throw new Error('Invalid client_id');
            }

            if (!client.allowForgotPassword) {
                throw new Error('Function not enabled for client');
            }

            const result = yield self.model.resetPassword(decodedToken.client_id, decodedToken.username, password);

            return result;
        });
    }

    public decodeJWT(jwt: string): Promise<string> {
        return new Promise((resolve, reject) => {
            jsonwebtoken.verify(jwt, 'my-secret', (err: Error, decodedCode: any) => {

                if (err) {
                    resolve(null);
                    return;
                }

                resolve(decodedCode);
            });
        });
    }

    private generateResetPasswordToken(client_id: string, username: string, return_url: string): string {
        return jsonwebtoken.sign({
            client_id,
            return_url,
            type: 'reset-password',
            username,
        }, 'my-secret', {
                expiresIn: '60m',
            });
    }

    private generateEmailVerificationToken(client_id: string, username: string, return_url: string): string {
        return jsonwebtoken.sign({
            client_id,
            return_url,
            type: 'email-verification',
            username,
        }, 'my-secret', {
                expiresIn: '60m',
            });
    }

    private generateAccessToken(client_id: string, username: string, scopes: string[]): string {
        return jsonwebtoken.sign({
            client_id,
            scopes,
            type: 'access-token',
            username,
        }, 'my-secret', {
                expiresIn: '60m',
            });
    }

    private generateCode(client_id: string, username: string, scopes: string[]): string {
        return jsonwebtoken.sign({
            client_id,
            scopes,
            type: 'code',
            username,
        }, 'my-secret', {
                expiresIn: '10m',
            });
    }
}
