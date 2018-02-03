import * as bodyParser from 'body-parser';
import * as express from 'express';
import * as path from 'path';
import * as yargs from 'yargs';

import { Client, OAuth2Framework, OAuth2FrameworkRouter } from './index';

const argv = yargs.argv;
const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
// app.use('/api/docs', express.static(path.join(__dirname, './../apidoc')));
// app.use('/api/coverage', express.static(path.join(__dirname, './../coverage/lcov-report')));

const model: any = {
    findClient: (client_id: string, request: express.Request) => {
        if (client_id === '0zyrWYATtw') {
            return Promise.resolve(new Client(
                'Demo Application',
                '0zyrWYATtw',
                'x3h8CTB2Cj',
                [],
                ['http://example.com/callback'],
                true,
                true));

        } else {
            return Promise.resolve(null);
        }
    },
    generateAccessToken: (client_id: string, userName: string, scopes: string[], request: express.Request) => {
        return Promise.resolve(null);
    },
    generateCode: (client_id: string, userName: string, scopes: string[], request: express.Request) => {
        return Promise.resolve(null);
    },
    register: (client_id: string, emailAddress: string, userName: string, password: string, request: express.Request) => {
        return Promise.resolve(null);
    },
    resetPassword: (client_id: string, userName: string, password: string, request: express.Request) => {
        return Promise.resolve(null);
    },
    sendForgotPasswordEmail: (client_id: string, userName: string, resetPasswordUrl: string, request: express.Request) => {
        return Promise.resolve(null);
    },
    sendVerificationEmail: (client_id: string, emailAddress: string, userName: string, verificationUrl: string, request: express.Request) => {
        return Promise.resolve(null);
    },
    validateAccessToken: (access_token: string, request: express.Request) => {
        return Promise.resolve(null);
    },
    validateCode: (code: string, request: express.Request) => {
        return Promise.resolve(null);
    },
    validateCredentials: (client_id: string, userName: string, password: string, request: express.Request) => {
        return Promise.resolve(true);
    },
    verify: (client_id: string, userName: string, request: express.Request) => {
        return Promise.resolve(null);
    },
};

function validEmailAddress(emailAddress: string): boolean {
    const emailAddressPattern = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    if (!emailAddressPattern.test(emailAddress)) {
        return false;
    }

    return true;
}

app.use('/', OAuth2FrameworkRouter(
    model,
    null,
    null,
    null,
    null,
    null,
    null,
    null,
    null,
    null,
    null,
    'qUKNuGEUFO',
));

app.get('/', (req: express.Request, res: express.Response) => {
    const client_id: string = '0zyrWYATtw';
    const redirect_uri: string = 'http://example.com/callback';

    res.redirect(`/authorize?response_type=code&client_id=${client_id}&redirect_uri=${redirect_uri}&state=custom-state`);
});

app.listen(argv.port || 3000, () => {
    console.log(`listening on port ${argv.port || 3000}`);
});
