// Imports
import * as bodyParser from 'body-parser';
import * as express from 'express';
import * as path from 'path';
import * as yargs from 'yargs';

import { Client, OAuth2Framework, OAuth2FrameworkRouter } from './index';

const argv = yargs.argv;
const app = express();

// Configures middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use('/api/docs', express.static(path.join(__dirname, './../apidoc')));
app.use('/api/coverage', express.static(path.join(__dirname, './../coverage/lcov-report')));

const model: any = {
    findClient: (client_id: string) => {
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
    register: (client_id: string, emailAddress: string, username: string, password: string) => {
        if (validEmailAddress(emailAddress)) {
            return Promise.resolve(true);
        } else {
            throw new Error('Invalid Email Address');
        }
    },
    resetPassword: (client_id: string, username: string, password: string) => {
        return Promise.resolve(true);
    },
    sendForgotPasswordEmail: (client_id: string, username: string, resetPasswordUrl: string) => {
        return Promise.resolve(true);
    },
    sendVerificationEmail: (client_id: string, emailAddress: string, username: string, verificationUrl: string) => {
        return Promise.resolve(true);
    },
    validateCredentials: (client_id: string, username: string, password: string) => {
        return Promise.resolve(true);
    },
    verify: (client_id: string, username: string) => {
        return Promise.resolve(true);
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

app.listen(argv.port || 3000, () => {
    console.log(`listening on port ${argv.port || 3000}`);
});
