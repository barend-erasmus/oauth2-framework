export class OAuth2FrameworkError extends Error {
    constructor(
        public code: string,
        public detailedMessage: string,
    ) {
        super(detailedMessage);
    }
}
