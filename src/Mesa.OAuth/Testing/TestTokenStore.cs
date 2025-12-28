namespace Mesa.OAuth.Testing
{
    using System;
    using Mesa.OAuth.Framework;
    using Mesa.OAuth.Framework.Interfaces;
    using Mesa.OAuth.Storage;
    using Mesa.OAuth.Storage.Interfaces;

    public class TestTokenStore : ITokenStore
    {
        public const string AccessSecret = "accesssecret";

        public const string RequestSecret = "requestsecret";

        public TestTokenStore ( )
        {
            this.CallbackUrl = "http://localhost/callback";
            this.VerificationCode = "GzvVb5WjWfHKa/0JuFupaMyn"; // this is a example google oauth verification code
        }

        public string CallbackUrl { get; set; }

        public string VerificationCode { get; set; }

        public static IToken CreateAccessTokenForRequestToken ( IOAuthContext requestContext )
        {
            EnsureTestConsumer ( requestContext );
            return new TokenBase
            {
                ConsumerKey = "key" ,
                Realm = null ,
                Token = "accesskey" ,
                TokenSecret = AccessSecret ,
                SessionHandle = "sessionHandle"
            };
        }

        public void ConsumeAccessToken ( IOAuthContext accessContext )
        {
            EnsureTestConsumer ( accessContext );

            if ( accessContext.Token != "accesskey" )
            {
                throw new OAuthException ( accessContext , OAuthProblems.TokenRejected ,
                                         "The supplied access token is unknown to the provider." );
            }
        }

        public void ConsumeRequestToken ( IOAuthContext requestContext )
        {
            EnsureTestConsumer ( requestContext );

            if ( requestContext.Token != "requestkey" )
            {
                throw new OAuthException ( requestContext , OAuthProblems.TokenRejected ,
                                         "The supplied request token is unknown to the provider." );
            }
        }

        public IToken CreateAccessToken ( IOAuthContext context )
        {
            EnsureTestConsumer ( context );
            return new TokenBase
            {
                ConsumerKey = "key" ,
                Realm = null ,
                Token = "accesskey" ,
                TokenSecret = AccessSecret ,
                SessionHandle = "sessionHandle"
            };
        }

        public IToken CreateRequestToken ( IOAuthContext context )
        {
            EnsureTestConsumer ( context );

            return new TokenBase
            {
                ConsumerKey = "key" ,
                Realm = null ,
                Token = "requestkey" ,
                TokenSecret = RequestSecret
            };
        }

        public IToken GetAccessTokenAssociatedWithRequestToken ( IOAuthContext requestContext )
        {
            EnsureTestConsumer ( requestContext );

            return requestContext.Token != "requestkey"
                ? throw new OAuthException ( requestContext , OAuthProblems.TokenRejected , "Expected Token \"requestkey\"" )
                : ( IToken ) new TokenBase
                {
                    ConsumerKey = "key" ,
                    Realm = null ,
                    Token = "accesskey" ,
                    TokenSecret = AccessSecret
                };
        }

        public string GetAccessTokenSecret ( IOAuthContext context )
        {
            return AccessSecret;
        }

        public string GetCallbackUrlForToken ( IOAuthContext requestContext )
        {
            return this.CallbackUrl;
        }

        public string GetRequestTokenSecret ( IOAuthContext context )
        {
            return RequestSecret;
        }

        public RequestForAccessStatus GetStatusOfRequestForAccess ( IOAuthContext requestContext )
        {
            return requestContext.ConsumerKey == "key" && requestContext.Token == "requestkey"
                ? RequestForAccessStatus.Granted
                : RequestForAccessStatus.Unknown;
        }

        public string GetVerificationCodeForRequestToken ( IOAuthContext requestContext )
        {
            return this.VerificationCode;
        }

        public IToken RenewAccessToken ( IOAuthContext requestContext )
        {
            EnsureTestConsumer ( requestContext );

            return new TokenBase
            {
                ConsumerKey = "key" ,
                Realm = null ,
                Token = "accesskey" ,
                TokenSecret = AccessSecret ,
                SessionHandle = requestContext.SessionHandle
            };
        }

        private static void EnsureTestConsumer ( IConsumer consumer )
        {
            ArgumentNullException.ThrowIfNull ( consumer );

            if ( consumer is OAuthContext context )
            {
                if ( consumer.Realm != null )
                {
                    throw new OAuthException (
                        context ,
                        OAuthProblems.ConsumerKeyRejected ,
                        "supplied realm was unknown to the provider" );
                }

                if ( consumer.ConsumerKey != "key" )
                {
                    throw new OAuthException (
                        context ,
                        OAuthProblems.ConsumerKeyRejected ,
                        "supplied consumer key was unknown to the provider" );
                }
            }
        }
    }
}