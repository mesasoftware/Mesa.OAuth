namespace Mesa.OAuth.Storage.Basic
{
    using System;
    using Mesa.OAuth.Framework;
    using Mesa.OAuth.Framework.Interfaces;
    using Mesa.OAuth.Storage.Basic.Interfaces;
    using Mesa.OAuth.Storage.Interfaces;
    using Mesa.OAuth.Utility;

    public class SimpleTokenStore : ITokenStore
    {
        private readonly ITokenRepository<AccessToken> accessTokenRepository;

        private readonly ITokenRepository<RequestToken> requestTokenRepository;

        public SimpleTokenStore ( ITokenRepository<AccessToken> accessTokenRepository , ITokenRepository<RequestToken> requestTokenRepository )
        {
            ArgumentNullException.ThrowIfNull ( accessTokenRepository );

            ArgumentNullException.ThrowIfNull ( requestTokenRepository );

            this.accessTokenRepository = accessTokenRepository;
            this.requestTokenRepository = requestTokenRepository;
        }

        public void ConsumeAccessToken ( IOAuthContext accessContext )
        {
            var accessToken = this.GetAccessToken ( accessContext );

            if ( accessToken.ExpiryDate < Clock.Now )
            {
                throw new OAuthException ( accessContext , OAuthProblems.TokenExpired , "Token has expired" );
            }
        }

        public void ConsumeRequestToken ( IOAuthContext requestContext )
        {
            ArgumentNullException.ThrowIfNull ( requestContext );

            var requestToken = this.GetRequestToken ( requestContext );

            UseUpRequestToken ( requestContext , requestToken );

            this.requestTokenRepository.SaveToken ( requestToken );
        }

        /// <summary>
        /// Create an access token using xAuth.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <returns></returns>
        public IToken CreateAccessToken ( IOAuthContext context )
        {
            ArgumentNullException.ThrowIfNull ( context );

            var accessToken = new AccessToken
            {
                ConsumerKey = context.ConsumerKey ,
                ExpiryDate = DateTime.UtcNow.AddDays ( 20 ) ,
                Realm = context.Realm ,
                Token = Guid.NewGuid ( ).ToString ( ) ,
                TokenSecret = Guid.NewGuid ( ).ToString ( ) ,
                UserName = Guid.NewGuid ( ).ToString ( ) ,
            };

            this.accessTokenRepository.SaveToken ( accessToken );

            return accessToken;
        }

        public IToken CreateRequestToken ( IOAuthContext context )
        {
            ArgumentNullException.ThrowIfNull ( context );

            var token = new RequestToken
            {
                ConsumerKey = context.ConsumerKey ,
                Realm = context.Realm ,
                Token = Guid.NewGuid ( ).ToString ( ) ,
                TokenSecret = Guid.NewGuid ( ).ToString ( ) ,
                CallbackUrl = context.CallbackUrl
            };

            this.requestTokenRepository.SaveToken ( token );

            return token;
        }

        public IToken? GetAccessTokenAssociatedWithRequestToken ( IOAuthContext requestContext )
        {
            var requestToken = this.GetRequestToken ( requestContext );

            return requestToken.AccessToken;
        }

        public string? GetAccessTokenSecret ( IOAuthContext context )
        {
            var token = this.GetAccessToken ( context );

            return token.TokenSecret;
        }

        public string? GetCallbackUrlForToken ( IOAuthContext requestContext )
        {
            var requestToken = this.GetRequestToken ( requestContext );
            return requestToken.CallbackUrl;
        }

        public string? GetRequestTokenSecret ( IOAuthContext context )
        {
            var requestToken = this.GetRequestToken ( context );

            return requestToken.TokenSecret;
        }

        public RequestForAccessStatus GetStatusOfRequestForAccess ( IOAuthContext accessContext )
        {
            var request = this.GetRequestToken ( accessContext );

            return request.AccessDenied
                ? RequestForAccessStatus.Denied
                : request.AccessToken == null ? RequestForAccessStatus.Unknown : RequestForAccessStatus.Granted;
        }

        public IToken? GetToken ( IOAuthContext context )
        {
            IToken? token = null;

            if ( !string.IsNullOrEmpty ( context.Token ) )
            {
                try
                {
                    token = this.accessTokenRepository.GetToken ( context.Token ) ??
                            ( IToken ) this.requestTokenRepository.GetToken ( context.Token );
                }
                catch ( Exception ex )
                {
                    // TODO: log exception
                    throw Error.UnknownToken ( context , context.Token , ex );
                }
            }

            return token;
        }

        public string? GetVerificationCodeForRequestToken ( IOAuthContext requestContext )
        {
            var requestToken = this.GetRequestToken ( requestContext );

            return requestToken.Verifier;
        }

        public IToken RenewAccessToken ( IOAuthContext requestContext )
        {
            throw new NotImplementedException ( );
        }

        private static void UseUpRequestToken ( IOAuthContext requestContext , RequestToken requestToken )
        {
            if ( requestToken.UsedUp )
            {
                throw new OAuthException ( requestContext , OAuthProblems.TokenRejected ,
                                         "The request token has already be consumed." );
            }

            requestToken.UsedUp = true;
        }

        private AccessToken GetAccessToken ( IOAuthContext context )
        {
            try
            {
                return this.accessTokenRepository.GetToken ( context.Token );
            }
            catch ( Exception exception )
            {
                // TODO: log exception
                throw Error.UnknownToken ( context , context.Token ?? string.Empty , exception );
            }
        }

        private RequestToken GetRequestToken ( IOAuthContext context )
        {
            try
            {
                return this.requestTokenRepository.GetToken ( context.Token );
            }
            catch ( Exception exception )
            {
                // TODO: log exception
                throw Error.UnknownToken ( context , context.Token ?? string.Empty , exception );
            }
        }
    }
}