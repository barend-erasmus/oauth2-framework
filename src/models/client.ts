export class Client {
    constructor(
        public name: string,
        public id: string,
        public secret: string,
        public allowedScopes: string[],
        public redirectUris: string[],
        public allowForgotPassword: boolean,
        public allowRegister: boolean,
    ) {

    }
}
