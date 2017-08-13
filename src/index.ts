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
        findClient: (client_id: string) => Promise<Client>
        validateCredentials: (client_id: string, username: string, password: string) => Promise<boolean>,
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

                const decodedCode: any = yield self.decodeCodeOrAccessToken(code);

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

            const decodedToken: any = yield self.decodeCodeOrAccessToken(access_token);

            if (!decodedToken) {
                return false;
            }

            if (decodedToken.type !== 'access-token') {
                return false;
            }

            return true;
        });
    }

    public forgotPasswordRequest(client_id: string, username: string, response_type: string, redirect_uri: string, state: string): Promise<boolean> {
        const self = this;

        return co(function* () {
            return false;
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

    private decodeCodeOrAccessToken(code: string): Promise<string> {
        return new Promise((resolve, reject) => {
            jsonwebtoken.verify(code, 'my-secret', (err: Error, decodedCode: any) => {

                if (err) {
                    resolve(null);
                    return;
                }

                resolve(decodedCode);
            });
        });
    }
}
