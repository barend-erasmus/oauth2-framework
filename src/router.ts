import * as express from 'express';
import * as fs from 'fs';
import * as Handlebars from 'handlebars';
import * as path from 'path';
import { Client, OAuth2Framework, OAuth2FrameworkError, Token } from './index';

export function OAuth2FrameworkRouter(
    model: {
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
    secret: string,
): express.Router {
    const router = express.Router();

    const framework: OAuth2Framework = new OAuth2Framework(model, secret);

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
    router.get('/authorize', async (req, res) => {

        try {
            const client: Client = await framework.model.findClient(req.query.client_id, req);

            if (!client) {
                throw new OAuth2FrameworkError('invalid_client_id', 'Invalid client id');
            }

            renderPage(res, loginPagePath || path.join(__dirname, 'views/login.handlebars'), {
                client,
                query: req.query,
            }, 200);

        } catch (err) {
            res.status(500).send(err);
        }
    });

    router.post('/authorize', async (req, res) => {
        try {
            const result: string = await framework.authorizationRequest(
                req.query.response_type,
                req.query.client_id,
                req.query.redirect_uri,
                req.query.scope ? [req.query.scope] : [],
                req.query.state,
                req.body.username,
                req.body.password,
                req);

            const client: Client = await framework.model.findClient(req.query.client_id, req);

            if (req.query.response_type === 'code') {
                res.redirect(`${req.query.redirect_uri}?code=${result}&state=${req.query.state}`);
            } else if (req.query.response_type === 'token') {
                res.redirect(`${req.query.redirect_uri}?access_token=${result}&state=${req.query.state}`);
            }
        } catch (err) {

            try {
                const client: Client = await framework.model.findClient(req.query.client_id, req);

                renderPage(res, loginPagePath || path.join(__dirname, 'views/login.handlebars'), {
                    client,
                    message: err.detailedMessage,
                    query: req.query,
                }, 200);
            } catch (err) {
                res.status(500).send(err);
            }
        }
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
    router.post('/token', async (req, res) => {
        try {
            const accessToken: string = await framework.accessTokenRequest(
                req.body.grant_type,
                req.body.code,
                req.body.redirect_uri,
                req.body.client_id,
                req.body.client_secret,
                req.body.username,
                req.body.password,
                [req.body.scope],
                req);

            res.json({
                access_token: accessToken,
            });
        } catch (err) {
            res.status(500).send(err);
        }
    });

    /**
     * @api {post} /validate Validate Request
     * @apiName ValidateRequest
     * @apiGroup OAuth2
     *
     * @apiHeader {string} authorization Bearer Token.
     */
    router.post('/validate', async (req, res) => {
        try {

            const access_token: string = getAuthorizationToken(req);

            const valid: boolean = await framework.validateAccessToken(access_token, req);

            res.json({
                valid,
            });
        } catch (err) {
            res.status(500).send(err);
        }
    });

    /**
     * @api {get} /user User Request
     * @apiName UserRequest
     * @apiGroup OAuth2
     *
     * @apiHeader {string} authorization Bearer Token.
     */
    router.get('/user', async (req, res) => {
        try {

            const access_token: string = getAuthorizationToken(req);

            const valid: boolean = await framework.validateAccessToken(access_token, req);

            if (valid) {
                const decodedToken: Token = await framework.decodeAccessToken(access_token, null);

                res.json(decodedToken);
            } else {
                res.json(null);
            }
        } catch (err) {
            res.status(500).send(err);
        }
    });

    router.get('/forgot-password', async (req, res) => {

        try {

            const client: Client = await framework.model.findClient(req.query.client_id, req);

            if (!client) {
                throw new OAuth2FrameworkError('invalid_client_id', 'Invalid client id');
            }

            renderPage(res, forgotPasswordPagePath || path.join(__dirname, 'views/forgot-password.handlebars'), {
                client,
                query: req.query,
            }, 200);

        } catch (err) {
            res.status(500).send(err);
        }
    });

    router.post('/forgot-password', async (req, res) => {

        try {

            const client: Client = await framework.model.findClient(req.query.client_id, req);

            if (!client) {
                throw new OAuth2FrameworkError('invalid_client_id', 'Invalid client id');
            }

            try {

                const result: boolean = await framework.forgotPasswordRequest(
                    req.query.client_id,
                    req.body.username,
                    req.query.response_type,
                    req.query.redirect_uri,
                    req.query.state,
                    req);

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

            } catch (err) {
                renderPage(res, forgotPasswordPagePath || path.join(__dirname, 'views/forgot-password.handlebars'), {
                    client,
                    message: err.detailedMessage,
                    query: req.query,
                }, 200);
            }

        } catch (err) {
            res.status(500).send(err);
        }
    });

    router.get('/reset-password', async (req, res) => {

        try {

            const decodedToken: any = await framework.decodeResetPasswordToken(req.query.token);

            if (!decodedToken) {
                throw new OAuth2FrameworkError('invalid_token', 'Invalid token');
            }

            const client: Client = await framework.model.findClient(decodedToken.client_id, req);

            if (!client) {
                throw new OAuth2FrameworkError('invalid_client_id', 'Invalid client id');
            }

            renderPage(res, resetPasswordPagePath || path.join(__dirname, 'views/reset-password.handlebars'), {
                client,
                query: req.query,
            }, 200);
        } catch (err) {
            res.status(500).send(err);
        }
    });

    router.post('/reset-password', async (req, res) => {

        try {

            const decodedToken: any = await framework.decodeResetPasswordToken(req.query.token);

            if (!decodedToken) {
                throw new OAuth2FrameworkError('invalid_token', 'Invalid token');
            }

            const client: Client = await framework.model.findClient(decodedToken.client_id, req);

            if (!client) {
                throw new OAuth2FrameworkError('invalid_client_id', 'Invalid client id');
            }

            try {

                const result: boolean = await framework.resetPasswordRequest(
                    req.query.token,
                    req.body.password,
                    req);

                if (result) {
                    res.redirect(decodedToken.return_url);
                } else {
                    renderPage(res, resetPasswordPagePath || path.join(__dirname, 'views/reset-password.handlebars'), {
                        client,
                        query: req.query,
                    }, 200);
                }
            } catch (err) {
                renderPage(res, resetPasswordPagePath || path.join(__dirname, 'views/reset-password.handlebars'), {
                    client,
                    message: err.detailedMessage,
                    query: req.query,
                }, 200);
            }
        } catch (err) {
            res.status(500).send(err);
        }
    });

    router.get('/register', async (req, res) => {

        try {
            const client: Client = await framework.model.findClient(req.query.client_id, req);

            if (!client) {
                throw new OAuth2FrameworkError('invalid_client_id', 'Invalid client id');
            }

            renderPage(res, registerPagePath || path.join(__dirname, 'views/register.handlebars'), {
                client,
                query: req.query,
            }, 200);

        } catch (err) {
            res.status(500).send(err);
        }
    });

    router.post('/register', async (req, res) => {

        try {

            const client: Client = await framework.model.findClient(req.query.client_id, req);

            if (!client) {
                throw new OAuth2FrameworkError('invalid_client_id', 'Invalid client id');
            }

            try {

                const result: boolean = await framework.registerRequest(
                    req.query.client_id,
                    req.body.emailAddress,
                    req.body.username,
                    req.body.password,
                    req.query.response_type,
                    req.query.redirect_uri,
                    req.query.state,
                    req);

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

            } catch (err) {
                renderPage(res, registerPagePath || path.join(__dirname, 'views/register.handlebars'), {
                    client,
                    message: err.detailedMessage,
                    query: req.query,
                }, 200);
            }

        } catch (err) {
            res.status(500).send(err);
        }
    });

    router.get('/email-verification', async (req, res) => {

        try {
            const decodedToken: any = await framework.decodeEmailVerificationToken(req.query.token);

            if (!decodedToken) {
                throw new OAuth2FrameworkError('invalid_token', 'Invalid token');
            }

            const client: Client = await framework.model.findClient(decodedToken.client_id, req);

            if (!client) {
                throw new OAuth2FrameworkError('invalid_client_id', 'Invalid client id');
            }

            const result: boolean = await framework.emailVerificationRequest(req.query.token, req);

            req.query.return_url = decodedToken.return_url;

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

        } catch (err) {
            res.status(500).send(err);
        }
    });

    return router;
}

function getAuthorizationToken(req: express.Request): string {
    const authorizationHeader: string = req.get('Authorization');

    const splittedAuthorizationHeader: string[] = authorizationHeader.split(' ');

    if (splittedAuthorizationHeader.length !== 2 && splittedAuthorizationHeader[0].toLowerCase() === 'bearer') {
            throw new OAuth2FrameworkError('invalid_authorization_header', 'Invalid header');
        }

    return splittedAuthorizationHeader[1];
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
