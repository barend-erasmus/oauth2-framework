// Imports
import * as co from 'co';
import * as express from 'express';
import * as fs from 'fs';
import * as Handlebars from 'handlebars';
import * as path from 'path';

import { Client, OAuth2Framework } from './index';

export function OAuth2FrameworkRouter(
    framework: OAuth2Framework,
    loginPagePath: string,
    forgotPasswordPagePath: string,
    forgotPasswordSuccessPagePath: string,
    forgotPasswordFailurePagePath: string
): express.Router {
    const router = express.Router();

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
                client: client,
                query: req.query
            }, 200);

        });
    });

    router.post('/authorize', (req, res) => {
        co(function* () {
            const result: string = yield framework.authorizationRequest(req.query.response_type, req.query.client_id, req.query.redirect_uri, [req.query.scope], req.query.state, req.body.username, req.body.password);

            const client: Client = yield framework.model.findClient(req.query.client_id);

            if (!result) {
                renderPage(res, loginPagePath || path.join(__dirname, 'views/login.handlebars'), {
                    client: client,
                    message: 'Invalid login credentials',
                    query: req.query
                }, 200);
                return;
            }

            if (req.query.response_type === 'code') {
                res.redirect(`${req.query.redirect_uri}?code=${result}&state=${req.query.state}`);
            } else if (req.query.response_type === 'token') {
                res.redirect(`${req.query.redirect_uri}?access_token=${result}&state=${req.query.state}`);
            }
        }).catch((err: Error) => {
            res.send(err.message);
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
            res.send(err.message);
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
            res.send(err.message);
        });
    });

    router.get('/forgot-password', (req, res) => {

        co(function* () {

            const client: Client = yield framework.model.findClient(req.query.client_id);

            if (!client) {
                throw new Error('Invalid client_id');
            }

            renderPage(res, forgotPasswordPagePath || path.join(__dirname, 'views/forgot-password.handlebars'), {
                client: client,
                query: req.query
            }, 200);

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
                    client: client,
                    query: req.query
                }, 200);
            } else {
                renderPage(res, forgotPasswordFailurePagePath || path.join(__dirname, 'views/forgot-password-failure.handlebars'), {
                    client: client,
                    query: req.query
                }, 200);
            }

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
