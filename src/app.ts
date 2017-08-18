// Imports
import * as bodyParser from 'body-parser';
import * as co from 'co';
import * as express from 'express';
import * as path from 'path';
import * as yargs from 'yargs';

import * as crypto from 'crypto';
import * as NeDB from 'nedb';
import * as sendgrid from 'sendgrid';

import { Client, OAuth2Framework, OAuth2FrameworkRouter } from './index';

const argv = yargs.argv;
const app = express();

// Configures middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use('/api/docs', express.static(path.join(__dirname, './../apidoc')));
app.use('/api/coverage', express.static(path.join(__dirname, './../coverage/lcov-report')));

const db = new NeDB({ filename: path.join(__dirname, 'database.dat'), autoload: true });

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

        return new Promise<boolean>((resolve, reject) => {
            db.findOne({
                client_id,
                username,
            }, (err: Error, doc: any) => {
                if (doc) {
                    resolve(false);
                } else {
                    db.insert({
                        client_id,
                        emailAddress,
                        password,
                        username,
                        verified: false,
                    });

                    resolve(true);
                }
            });
        });
    },
    resetPassword: (client_id: string, username: string, password: string) => {

        db.update({
            client_id,
            username,
            verified: true,
        }, {
                $set: {
                    password,
                },
            });

        return Promise.resolve(true);
    },
    sendForgotPasswordEmail: (client_id: string, username: string, resetPasswordUrl: string) => {
        return co(function* () {

            if (!validateEmailAddress(username)) {
                return true;
            }

            // const domain = 'https://oauth2-framework.openservices.co.za';
            const domain = 'http://localhost:3000';

            const subject = 'OAuth2 Framework - Forgot Password';
            const html = `<div> We heard that you lost your OAuth2 Framework password. Sorry about that!<br><br>But don’t worry! You can use the following link within the next day to reset your password:<br><br><a href="${domain}${resetPasswordUrl}" target="_blank">Reset Password</a><br><br>If you don’t use this link within 3 hours, it will expire.<br><br>Thanks,<br>Your friends at OAuth2 Framework <div class="yj6qo"></div><div class="adL"><br></div></div>`;

            return sendEmail(username, subject, html);
        });
    },
    sendVerificationEmail: (client_id: string, emailAddress: string, username: string, verificationUrl: string) => {
        return co(function* () {

            if (!validateEmailAddress(emailAddress)) {
                return true;
            }

            // const domain = 'https://oauth2-framework.openservices.co.za';
            const domain = 'http://localhost:3000';

            const subject = 'OAuth2 Framework - Verification';
            const html = `<div> Thank you for registering on OAuth2 Framework. <br><br><a href="${domain}${verificationUrl}" target="_blank">Verify Email</a> <br><br>If you don’t use this link within 3 hours, it will expire. <br><br>Thanks,<br>Your friends at OAuth2 Framework <div class="yj6qo"></div><div class="adL"><br></div></div>`;

            return sendEmail(emailAddress, subject, html);
        });
    },
    validateCredentials: (client_id: string, username: string, password: string) => {
        return new Promise<boolean>((resolve, reject) => {
            db.findOne({
                client_id,
                password,
                username,
                verified: true,
            }, (err: Error, doc: any) => {
                if (doc) {
                    resolve(true);
                } else {
                    resolve(false);
                }
            });
        });
    },
    verify: (client_id: string, username: string) => {

        db.update({
            client_id,
            username,
            verified: false,
        }, {
                $set: {
                    verified: true,
                },
            });

        return Promise.resolve(true);
    },
};

function validateEmailAddress(emailAddress: string): boolean {
    const emailAddressPattern = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    if (!emailAddressPattern.test(emailAddress)) {
        return false;
    }

    return true;
}

function sendEmail(toAddress: string, subject: string, html: string): Promise<boolean> {
    return new Promise((resolve, reject) => {

        const sendGridApiKey = '260a5841eef8050867e5fcf789494744a5d19f3729b7e20003d06e0c96fb70d888cd2d5ac7ba24253051229fa45156a31185676abf6b40e14b7515313340784a8915e1472f';

        const cipher = crypto.createDecipher('aes-256-ctr', 'BKReoyqSRE');
        let decryptedToken = cipher.update(sendGridApiKey, 'hex', 'utf8');
        decryptedToken += cipher.final('utf8');

        const helper = sendgrid.mail;

        const content = new helper.Content('text/html', html);
        const mail = new helper.Mail(new helper.Email('noreply@developersworkspace.co.za'), subject, new helper.Email(toAddress), content);

        const sg = sendgrid(decryptedToken);
        const request = sg.emptyRequest({
            body: mail.toJSON(),
            method: 'POST',
            path: '/v3/mail/send',
        });

        sg.API(request, (response: any) => {
            resolve(true);
        });
    });
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
));

app.listen(argv.port || 3000, () => {
    console.log(`listening on port ${argv.port || 3000}`);
});
