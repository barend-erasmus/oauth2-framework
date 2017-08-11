import * as express from 'express';
import * as co from 'co';
import * as bodyParser from 'body-parser';

import { OAuth2Framework, Client } from './index';

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

const framework = new OAuth2Framework({
    findClient: (client_id: string) => {
        return Promise.resolve(new Client(null, null, null, ['http://localhost:3000/callback']));
    },
    validateCredentials: (client_id: string, username: string, password: string) => {
        return Promise.resolve(true);
    }
})

app.get('/authorize', (req, res) => {

    res.send(
        `
<form method="post">
  <div class="container">
    <label><b>Username</b></label>
    <input type="text" placeholder="Enter Username" name="username" required>

    <label><b>Password</b></label>
    <input type="password" placeholder="Enter Password" name="password" required>

    <button type="submit">Login</button>
  </div>
</form>
`);

});

app.post('/authorize', function (req, res) {
    co(function* () {
        const result: string = yield framework.authorizationRequest(req.query.response_type, req.query.client_id, req.query.redirect_uri, [req.query.scope], req.query.state, req.body.username, req.body.password);

        if (req.query.response_type === 'code') {
            res.redirect(`${req.query.redirect_uri}?code=${result}&state=${req.query.state}`);
        } else if (req.query.response_type === 'token') {
            res.redirect(`${req.query.redirect_uri}?access_token=${result}&state=${req.query.state}`);
        }
    }).catch((err: Error) => {
        res.send(err.message);
    });
});

app.post('/token', (req, res) => {
    co(function* () {
        const accessToken: string = yield framework.accessTokenRequest(req.body.grant_type, req.body.code, req.body.redirect_uri, req.body.client_id, req.body.client_secret, req.body.username, req.body.password, [req.body.scope]);

        res.json({
            access_token: accessToken
        });
    }).catch((err: Error) => {
        res.send(err.message);
    });
});

app.listen(3000, () => {
    console.log('Example app listening on port 3000!');
});