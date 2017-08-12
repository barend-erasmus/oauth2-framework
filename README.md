# OAuth2 Framework

The OAuth 2.0 authorization framework enables a third-party    application to obtain limited access to an HTTP service, either on    behalf of a resource owner by orchestrating an approval interaction    between the resource owner and the HTTP service, or by allowing the    third-party application to obtain access on its own behalf.

## Getting Started

* [Demo (Authorization Code Grant)](https://oauth2-framework.openservices.co.za/authorize?response_type=code&client_id=0zyrWYATtw&redirect_uri=http://example.com/callback&scope=read&state=yAAOhrFDNH)
* [Demo (Implicit Grant)](https://oauth2-framework.openservices.co.za/authorize?response_type=token&client_id=0zyrWYATtw&redirect_uri=http://example.com/callback&scope=read&state=yAAOhrFDNH)
* [API Documentation](https://oauth2-framework.openservices.co.za/api/docs/)
* [Source Code](https://github.com/barend-erasmus/oauth2-framework)
* [Coverage Report](https://oauth2-framework.openservices.co.za/api/coverage/)

### Installation

`npm install --save oauth2-framework`

### Usage

```javascript

import { Client, OAuth2Framework, OAuth2FrameworkRouter } from 'oauth2-framework';

const framework = new OAuth2Framework({
    findClient: (client_id: string) => {
        if (client_id === '0zyrWYATtw') {
            return Promise.resolve(new Client('0zyrWYATtw', 'x3h8CTB2Cj', [], ['http://example.com/callback']));
        } else {
            return Promise.resolve(null);
        }
    },
    validateCredentials: (client_id: string, username: string, password: string) => {
        if (username.toLowerCase() === 'demo' && password === '123456') {
            return Promise.resolve(true);
        } else {
            return Promise.resolve(false);
        }
    },
});

app.use('/', OAuth2FrameworkRouter(framework, null));

app.listen(3000, () => {
    console.log(`listening on port 3000`);
});
```

## Support

* Authorization Code Grant
* Implicit Grant
* Resource Owner Password Credentials Grant


