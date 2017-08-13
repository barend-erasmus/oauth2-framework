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

const framework = new OAuth2Framework({
    findClient: (client_id: string) => {
        if (client_id === '0zyrWYATtw') {
            return Promise.resolve(new Client('Demo Application', '0zyrWYATtw', 'x3h8CTB2Cj', [], ['http://example.com/callback'], true));
        } else {
            return Promise.resolve(null);
        }
    },
    sendForgotPasswordEmail: (client_id: string, username: string, resetPasswordUrl: string) => {
        return Promise.resolve(true);
    },
    validateCredentials: (client_id: string, username: string, password: string) => {
        if (username.toLowerCase() === 'demo' && password === '123456') {
            return Promise.resolve(true);
        } else {
            return Promise.resolve(false);
        }
    },
});

app.use('/', OAuth2FrameworkRouter(framework, null, null, null, null));

app.listen(argv.port || 3000, () => {
    console.log(`listening on port ${argv.port || 3000}`);
});
