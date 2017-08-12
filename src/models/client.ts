export class Client {
    constructor(public id: string, public secret: string, public allowedScopes: string[], public redirectUris: string[]) {

    }
}
