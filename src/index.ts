import * as express from 'express';
import * as jsonwebtoken from 'jsonwebtoken';
import { Client } from './models/client';
import { OAuth2FrameworkError } from './models/oauth2-error';
import { Token } from './models/token';

export { Client } from './models/client';
export { Token } from './models/token';
export { OAuth2FrameworkRouter } from './router';
export { OAuth2FrameworkError } from './models/oauth2-error';

export class OAuth2Framework {

    constructor(public model: {
        findClient(client_id: string, request: express.Request): Promise<Client>,
        generateAccessToken(client_id: string, username: string, scopes: string[], request: express.Request): Promise<string>,
        generateCode(client_id: string, username: string, scopes: string[], request: express.Request): Promise<string>,
        register(client_id: string, emailAddress: string, username: string, password: string, request: express.Request): Promise<boolean>,
        resetPassword(client_id: string, username: string, password: string, request: express.Request): Promise<boolean>,
        sendForgotPasswordEmail(client_id: string, username: string, resetPasswordUrl: string, request: express.Request): Promise<boolean>,
        sendVerificationEmail(client_id: string, emailAddress: string, username: string, verificationUrl: string, request: express.Request): Promise<boolean>,
        validateAccessToken(access_token: string, request: express.Request): Promise<Token>,
        validateCode(code: string, request: express.Request): Promise<Token>,
        validateCredentials(client_id: string, username: string, password: string, request: express.Request): Promise<boolean>,
        verify(client_id: string, username: string, request: express.Request): Promise<boolean>,
    },          public secret: string,
    ) {

    }

    public async accessTokenRequest(
        grant_type: string,
        code: string,
        redirect_uri: string,
        client_id: string,
        client_secret: string,
        username: string,
        password: string,
        scopes: string[],
        request: express.Request): Promise<string> {

        this.throwIfInvalidGrantType(grant_type);

        const client: Client = await this.findClientAndValidate(client_id, redirect_uri, scopes, request);

        if (grant_type === 'password') {
            const validCredentials: boolean = await this.model.validateCredentials(
                client_id,
                username,
                password,
                request);

            this.throwIfInvalidCredentials(validCredentials);

            return this.model.generateAccessToken(client_id, username, scopes, request);
        } else if (grant_type === 'authorization_code') {

            this.throwIfClientDoesNotMatchClientSecret(client, client_secret);

            const token: Token = await this.model.validateCode(code, request);

            return this.model.generateAccessToken(
                token.client_id,
                token.username,
                token.scopes,
                request);
        }
    }

    public async authorizationRequest(
        response_type: string,
        client_id: string,
        redirect_uri: string,
        scopes: string[],
        state: string,
        username: string,
        password: string,
        request: express.Request): Promise<string> {

        this.throwIfInvalidResponseType(response_type);

        const client: Client = await this.findClientAndValidate(client_id, redirect_uri, scopes, request);

        const validCredentials: boolean = await this.model.validateCredentials(client_id, username, password, request);

        this.throwIfInvalidCredentials(validCredentials);

        switch (response_type) {
            case 'code':
                return this.model.generateCode(client_id, username, scopes, request);
            case 'token':
                return this.model.generateAccessToken(client_id, username, scopes, request);
        }
    }

    public async validateAccessToken(access_token: string, request: express.Request): Promise<boolean> {
        const token: Token = await this.model.validateAccessToken(access_token, request);

        if (!token) {
            return false;
        }

        return true;
    }

    public async decodeAccessToken(access_token: string, request: express.Request): Promise<Token> {
        const token: Token = await this.model.validateAccessToken(access_token, request);

        if (!token) {
            return null;
        }

        return token;
    }

    public async forgotPasswordRequest(
        client_id: string,
        username: string,
        response_type: string,
        redirect_uri: string,
        state: string,
        request: express.Request): Promise<boolean> {

        const client: Client = await this.model.findClient(client_id, request);

        this.throwIfClientNull(client);

        if (!client.allowForgotPassword) {
            throw new OAuth2FrameworkError('forgot_password_not_enabled', 'The forgot password functionality is not enabled for this client.');
        }

        const returnUrl = `authorize?response_type=${response_type}&client_id=${client_id}&redirect_uri=${redirect_uri}&state=${state}`;
        const resetPasswordToken = this.generateResetPasswordToken(client_id, username, returnUrl);

        const resetPasswordUrl = `/reset-password?token=${resetPasswordToken}`;

        const result = await this.model.sendForgotPasswordEmail(
            client_id,
            username,
            resetPasswordUrl,
            request);

        return result;
    }

    public async emailVerificationRequest(token: string, request: express.Request): Promise<boolean> {
        const decodedToken: any = await this.decodeEmailVerificationToken(token);

        if (!decodedToken) {
            throw new OAuth2FrameworkError('invalid_token', 'Invalid token');
        }

        const client: Client = await this.model.findClient(decodedToken.client_id, request);

        this.throwIfClientNull(client);

        if (!client.allowRegister) {
            throw new OAuth2FrameworkError('register_not_enabled', 'The register functionality is not enabled for this client.');
        }

        const result = await this.model.verify(
            decodedToken.client_id,
            decodedToken.username,
            request);

        return result;
    }

    public async registerRequest(
        client_id: string,
        emailAddress: string,
        username: string,
        password: string,
        response_type: string,
        redirect_uri: string,
        state: string,
        request: express.Request): Promise<boolean> {
        const client: Client = await this.model.findClient(client_id, request);

        this.throwIfClientNull(client);

        if (!client.allowRegister) {
            throw new OAuth2FrameworkError('register_not_enabled', 'The register functionality is not enabled for this client.');
        }

        const returnUrl = `authorize?response_type=${response_type}&client_id=${client_id}&redirect_uri=${redirect_uri}&state=${state}`;

        const emailVerificationToken = this.generateEmailVerificationToken(
            client_id,
            username,
            returnUrl);

        const emailVerificationUrl = `/email-verification?token=${emailVerificationToken}`;

        const result = await this.model.register(client_id, emailAddress, username, password, request);

        if (result) {
            const emailResult = await this.model.sendVerificationEmail(
                client_id, emailAddress,
                username,
                emailVerificationUrl,
                request);
        }

        return result;
    }

    public async resetPasswordRequest(token: string,
                                      password: string,
                                      request: express.Request): Promise<boolean> {

        const decodedToken: any = await this.decodeResetPasswordToken(token);

        if (!decodedToken) {
             throw new OAuth2FrameworkError('invalid_token', 'Invalid token');
        }

        const client: Client = await this.model.findClient(decodedToken.client_id, request);

        this.throwIfClientNull(client);

        if (!client.allowForgotPassword) {
            throw new OAuth2FrameworkError('forgot_password_not_enabled', 'The forgot password functionality is not enabled for this client.');
        }

        const result = await this.model.resetPassword(
            decodedToken.client_id,
            decodedToken.username,
            password,
            request);

        return result;
    }

    public async decodeResetPasswordToken(token: string): Promise<any> {

        const decodedToken: any = await this.decodeJWT(token);

        if (!decodedToken) {
            return null;
        }

        if (decodedToken.type !== 'reset-password') {
            return null;
        }

        return decodedToken;
    }

    public async decodeEmailVerificationToken(token: string): Promise<any> {
        const decodedToken: any = await this.decodeJWT(token);

        if (!decodedToken) {
            return null;
        }

        if (decodedToken.type !== 'email-verification') {
            return null;
        }

        return decodedToken;
    }

    private decodeJWT(jwt: string): Promise<string> {
        return new Promise((resolve, reject) => {
            jsonwebtoken.verify(jwt, this.secret, (err: Error, decodedCode: any) => {

                if (err) {
                    resolve(null);
                    return;
                }

                resolve(decodedCode);
            });
        });
    }

    private async findClientAndValidate(client_id: string, redirect_uri: string, scopes: string[], request: express.Request): Promise<Client> {
        const client: Client = await this.model.findClient(client_id, request);

        this.throwIfClientNull(client);

        this.throwIfClientDoesNotContainUri(client, redirect_uri);

        this.throwIfClientDoesNotContainScope(client, scopes);

        return client;
    }

    private generateEmailVerificationToken(
        client_id: string,
        username: string,
        return_url: string): string {
        return jsonwebtoken.sign({
            client_id,
            return_url,
            type: 'email-verification',
            username,
        }, this.secret, {
                expiresIn: '60m',
            });
    }

    private generateResetPasswordToken(
        client_id: string,
        username: string,
        return_url: string): string {
        return jsonwebtoken.sign({
            client_id,
            return_url,
            type: 'reset-password',
            username,
        }, this.secret, {
                expiresIn: '60m',
            });
    }

    private throwIfClientDoesNotContainScope(client: Client, scopes: string[]): void {
        if (scopes.length !== 0 && scopes.filter((x) => client.allowedScopes.indexOf(x) === -1).length !== 0) {
            throw new OAuth2FrameworkError('invalid_scopes', 'Invalid scopes');
        }
    }

    private throwIfClientDoesNotContainUri(client: Client, uri: string): void {
        if (client.redirectUris.indexOf(uri) === -1) {
            throw new OAuth2FrameworkError('invalid_redirect_uri', 'Invalid redirect uri');
        }
    }

    private throwIfClientDoesNotMatchClientSecret(client: Client, client_secret: string): void {
        if (client.secret !== client_secret) {
            throw new OAuth2FrameworkError('invalid_secret', 'Invalid client_secret');
        }
    }

    private throwIfClientNull(client: Client): void {
        if (!client) {
            throw new OAuth2FrameworkError('invalid_client_id', 'Invalid client id');
        }
    }

    private throwIfInvalidCredentials(validCredentials: boolean): void {
        if (!validCredentials) {
            throw new OAuth2FrameworkError('invalid_credentials', 'Invalid credentials');
        }
    }

    private throwIfInvalidGrantType(grant_type: string): void {
        if (grant_type !== 'authorization_code' && grant_type !== 'password') {
            throw new OAuth2FrameworkError('invalid_grant_type', 'Invalid grant type');
        }
    }

    private throwIfInvalidResponseType(response_type: string): void {
        if (response_type !== 'code' && response_type !== 'token') {
            throw new OAuth2FrameworkError('invalid_response_type', 'Invalid response type');
        }
    }
}
