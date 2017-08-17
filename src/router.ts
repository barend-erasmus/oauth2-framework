// Imports
import * as co from 'co';
import * as express from 'express';
import * as fs from 'fs';
import * as Handlebars from 'handlebars';
import * as path from 'path';

import { Client, OAuth2Framework } from './index';

export function OAuth2FrameworkRouter(
    model: {
        findClient: (client_id: string) => Promise<Client>,
        register: (client_id: string, emailAddress: string, username: string, password: string) => Promise<boolean>,
        resetPassword: (client_id: string, username: string, password: string) => Promise<boolean>,
        sendForgotPasswordEmail: (client_id: string, username: string, resetPasswordUrl: string) => Promise<boolean>,
        sendVerificationEmail: (client_id: string, emailAddress: string, username: string, verificationUrl: string) => Promise<boolean>,
        validateCredentials: (client_id: string, username: string, password: string) => Promise<boolean>,
    },
    loginPagePath: string,
    forgotPasswordPagePath: string,
    forgotPasswordSuccessPagePath: string,
    forgotPasswordFailurePagePath: string,
    resetPasswordPagePath: string,
    registerPagePath: string,
    registerSuccessPagePath: string,
    registerFailurePagePath: string,
    emailVerficationSuccessPagePath: string,
    emailVerficationFailurePagePath: string,
): express.Router {
    const router = express.Router();

    const framework: OAuth2Framework = new OAuth2Framework(model);

    /**
     * @api {get} /authorize Authorization Request
     * @apiName AuthorizationRequest
     * @apiGroup OAuth2
     *
     * @apiParam {string} response_type The authorization endpoint is used by the authorization code grant type and implicit grant type flows
     * @apiParam {string} client_id The client identifier issued to the client during the registration process
     * @apiParam {string} redirect_uri After completing its interaction with the resource owner, the authorization server directs the resource owner's user-agent back to the client
     * @apiParam {string} scope The scope of the access request
     * @apiParam {string} state An opaque value used by the client to maintain state between the request and callback
     *
     */
    router.get('/authorize', (req, res) => {

        co(function* () {

            const client: Client = yield framework.model.findClient(req.query.client_id);

            if (!client) {
                throw new Error('Invalid client_id');
            }

            renderPage(res, loginPagePath || path.join(__dirname, 'views/login.handlebars'), {
                client,
                query: req.query,
            }, 200);

        }).catch((err: Error) => {
            res.status(500).send(err.message);
        });
    });

    router.post('/authorize', (req, res) => {
        co(function* () {
            const result: string = yield framework.authorizationRequest(req.query.response_type, req.query.client_id, req.query.redirect_uri, [req.query.scope], req.query.state, req.body.username, req.body.password);

            const client: Client = yield framework.model.findClient(req.query.client_id);

            if (!result) {
                renderPage(res, loginPagePath || path.join(__dirname, 'views/login.handlebars'), {
                    client,
                    message: 'Invalid login credentials',
                    query: req.query,
                }, 200);
                return;
            }

            if (req.query.response_type === 'code') {
                res.redirect(`${req.query.redirect_uri}?code=${result}&state=${req.query.state}`);
            } else if (req.query.response_type === 'token') {
                res.redirect(`${req.query.redirect_uri}?access_token=${result}&state=${req.query.state}`);
            }
        }).catch((err: Error) => {
            res.status(500).send(err.message);
        });
    });

    /**
     * @api {post} /token Access Token Request
     * @apiName AccessTokenRequest
     * @apiGroup OAuth2
     *
     * @apiParam {string} grant_type Grant Type
     * @apiParam {string} client_id The client identifier issued to the client during the registration process
     * @apiParam {string} client_secret The client secret
     * @apiParam {string} redirect_uri After completing its interaction with the resource owner, the authorization server directs the resource owner's user-agent back to the client
     * @apiParam {string} scope The scope of the access request
     * @apiParam {string} code The authorization code generated by the authorization server
     * @apiParam {string} username The username
     * @apiParam {string} password The password
     */
    router.post('/token', (req, res) => {
        co(function* () {
            const accessToken: string = yield framework.accessTokenRequest(req.body.grant_type, req.body.code, req.body.redirect_uri, req.body.client_id, req.body.client_secret, req.body.username, req.body.password, [req.body.scope]);

            res.json({
                access_token: accessToken,
            });
        }).catch((err: Error) => {
            res.status(500).send(err.message);
        });
    });

    /**
     * @api {post} /validate Validate Request
     * @apiName ValidateRequest
     * @apiGroup OAuth2
     *
     * @apiHeader {string} authorization Bearer Token.
     */
    router.post('/validate', (req, res) => {
        co(function* () {

            const authorizationHeader: string = req.get('Authorization');

            if (!authorizationHeader || authorizationHeader.split(' ')[0].toLowerCase() !== 'bearer') {
                throw new Error('Invalid header');
            }

            const access_token = authorizationHeader.split(' ')[1];

            const valid: boolean = yield framework.validateAccessToken(access_token);

            res.json({
                valid,
            });
        }).catch((err: Error) => {
            res.status(500).send(err.message);
        });
    });

    /**
     * @api {get} /user User Request
     * @apiName UserRequest
     * @apiGroup OAuth2
     *
     * @apiHeader {string} authorization Bearer Token.
     */
    router.get('/user', (req, res) => {
        co(function* () {

            const authorizationHeader: string = req.get('Authorization');

            if (!authorizationHeader || authorizationHeader.split(' ')[0].toLowerCase() !== 'bearer') {
                throw new Error('Invalid header');
            }

            const access_token = authorizationHeader.split(' ')[1];

            const valid: boolean = yield framework.validateAccessToken(access_token);

            if (valid) {
                const decodedToken: string = yield framework.decodeJWT(access_token);

                res.json(decodedToken);
            } else {
                res.json(null);
            }
        }).catch((err: Error) => {
            res.status(500).send(err.message);
        });
    });

    router.get('/forgot-password', (req, res) => {

        co(function* () {

            const client: Client = yield framework.model.findClient(req.query.client_id);

            if (!client) {
                throw new Error('Invalid client_id');
            }

            renderPage(res, forgotPasswordPagePath || path.join(__dirname, 'views/forgot-password.handlebars'), {
                client,
                query: req.query,
            }, 200);

        }).catch((err: Error) => {
            res.status(500).send(err.message);
        });
    });

    router.post('/forgot-password', (req, res) => {

        co(function* () {

            const client: Client = yield framework.model.findClient(req.query.client_id);

            if (!client) {
                throw new Error('Invalid client_id');
            }

            const result: boolean = yield framework.forgotPasswordRequest(req.query.client_id, req.body.username, req.query.response_type, req.query.redirect_uri, req.query.state);

            if (result) {
                renderPage(res, forgotPasswordSuccessPagePath || path.join(__dirname, 'views/forgot-password-success.handlebars'), {
                    client,
                    query: req.query,
                }, 200);
            } else {
                renderPage(res, forgotPasswordFailurePagePath || path.join(__dirname, 'views/forgot-password-failure.handlebars'), {
                    client,
                    query: req.query,
                }, 200);
            }

        }).catch((err: Error) => {
            res.status(500).send(err.message);
        });
    });

    router.get('/reset-password', (req, res) => {

        co(function* () {

            const decodedToken: any = yield framework.decodeResetPasswordToken(req.query.token);

            if (!decodedToken) {
                throw new Error('Invalid token');
            }

            const client: Client = yield framework.model.findClient(decodedToken.client_id);

            if (!client) {
                throw new Error('Invalid client_id');
            }

            renderPage(res, resetPasswordPagePath || path.join(__dirname, 'views/reset-password.handlebars'), {
                client,
                query: req.query,
            }, 200);
        }).catch((err: Error) => {
            res.status(500).send(err.message);
        });
    });

    router.post('/reset-password', (req, res) => {

        co(function* () {

            const decodedToken: any = yield framework.decodeResetPasswordToken(req.query.token);

            if (!decodedToken) {
                throw new Error('Invalid token');
            }

            const client: Client = yield framework.model.findClient(decodedToken.client_id);

            if (!client) {
                throw new Error('Invalid client_id');
            }

            const result: boolean = yield framework.resetPasswordRequest(req.query.token, req.body.password);

            if (result) {
                res.redirect(decodedToken.return_url);
            } else {
                renderPage(res, resetPasswordPagePath || path.join(__dirname, 'views/reset-password.handlebars'), {
                    client,
                    query: req.query,
                }, 200);
            }
        }).catch((err: Error) => {
            res.status(500).send(err.message);
        });
    });

    router.get('/register', (req, res) => {

        co(function* () {

            const client: Client = yield framework.model.findClient(req.query.client_id);

            if (!client) {
                throw new Error('Invalid client_id');
            }

            renderPage(res, registerPagePath || path.join(__dirname, 'views/register.handlebars'), {
                client,
                query: req.query,
            }, 200);

        }).catch((err: Error) => {
            res.status(500).send(err.message);
        });
    });

    router.post('/register', (req, res) => {

        co(function* () {

            const client: Client = yield framework.model.findClient(req.query.client_id);

            if (!client) {
                throw new Error('Invalid client_id');
            }

            const result: boolean = yield framework.registerRequest(req.query.client_id, req.body.emailAddress, req.body.username, req.body.password, req.query.response_type, req.query.redirect_uri, req.query.state);

            if (result) {
                renderPage(res, registerSuccessPagePath || path.join(__dirname, 'views/register-success.handlebars'), {
                    client,
                    query: req.query,
                }, 200);
            } else {
                renderPage(res, registerFailurePagePath || path.join(__dirname, 'views/register-failure.handlebars'), {
                    client,
                    query: req.query,
                }, 200);
            }

        }).catch((err: Error) => {
            res.status(500).send(err.message);
        });
    });

    router.get('/email-verification', (req, res) => {

        co(function* () {

            const decodedToken: any = yield framework.decodeEmailVerificationToken(req.query.token);

            if (!decodedToken) {
                throw new Error('Invalid token');
            }

            const client: Client = yield framework.model.findClient(decodedToken.client_id);

            if (!client) {
                throw new Error('Invalid client_id');
            }

            const result: boolean = yield framework.emailVerificationRequest(req.query.token);

            if (result) {
                renderPage(res, emailVerficationSuccessPagePath || path.join(__dirname, 'views/email-verification-success.handlebars'), {
                    client,
                    query: req.query,
                }, 200);
            } else {
                renderPage(res, emailVerficationFailurePagePath || path.join(__dirname, 'views/email-verification-failure.handlebars'), {
                    client,
                    query: req.query,
                }, 200);
            }

        }).catch((err: Error) => {
            res.status(500).send(err.message);
        });
    });


    return router;
}

function renderPage(res: express.Response, htmlFile: string, data: any, status: number): void {

    fs.readFile(htmlFile, 'utf8', (err: Error, html: string) => {
        if (err) {
            res.status(400).send(err.message);
            return;
        }

        const template = Handlebars.compile(html);

        const result = template(data);

        res.status(status).send(result);

    });
}
