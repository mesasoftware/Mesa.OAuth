namespace Mesa.OAuth.Consumer
{
    using System;
    using System.Collections;
    using System.Collections.Specialized;
    using System.Threading.Tasks;
    using System.Web;
    using Mesa.OAuth.Consumer.Interfaces;
    using Mesa.OAuth.Framework;
    using Mesa.OAuth.Framework.Interfaces;
    using Mesa.OAuth.Utility;

    [Serializable]
    public class OAuthSession : IOAuthSession
    {
        private readonly NameValueCollection cookies = [ ];

        private readonly NameValueCollection formParameters = [ ];

        private readonly NameValueCollection headers = [ ];

        private readonly NameValueCollection queryParameters = [ ];

        private IConsumerRequestFactory consumerRequestFactory = DefaultConsumerRequestFactory.Instance;

        public OAuthSession ( IOAuthConsumerContext consumerContext ) : this (
            consumerContext ,
            ( Uri? ) null ,
            null ,
            null ,
            null )
        {
        }

        public OAuthSession ( IOAuthConsumerContext consumerContext , Uri endPointUri )
            : this ( consumerContext , endPointUri , endPointUri , endPointUri , null )
        {
        }

        public OAuthSession ( IOAuthConsumerContext consumerContext , Uri requestTokenUri , Uri userAuthorizeUri , Uri accessTokenUri )
            : this ( consumerContext , requestTokenUri , userAuthorizeUri , accessTokenUri , null )
        {
        }

        public OAuthSession (
            IOAuthConsumerContext consumerContext ,
            Uri? requestTokenUri ,
            Uri? userAuthorizeUri ,
            Uri? accessTokenUri ,
            Uri? callBackUri )
        {
            this.ConsumerContext = consumerContext;
            this.RequestTokenUri = requestTokenUri;
            this.AccessTokenUri = accessTokenUri;
            this.UserAuthorizeUri = userAuthorizeUri;
            this.CallbackUri = callBackUri;
        }

        public OAuthSession (
            IOAuthConsumerContext consumerContext ,
            string requestTokenUrl ,
            string userAuthorizeUrl ,
            string accessTokenUrl ,
            string? callBackUrl ) : this (
                consumerContext ,
                new Uri ( requestTokenUrl ) ,
                new Uri ( userAuthorizeUrl ) ,
                new Uri ( accessTokenUrl ) ,
                ParseCallbackUri ( callBackUrl ) )
        {
        }

        public OAuthSession (
            IOAuthConsumerContext consumerContext ,
            string requestTokenUrl ,
            string userAuthorizeUrl ,
            string accessTokenUrl ) : this (
                consumerContext ,
                requestTokenUrl ,
                userAuthorizeUrl ,
                accessTokenUrl ,
                null )
        {
        }

        public IToken? AccessToken { get; set; }

        public Uri? AccessTokenUri { get; set; }

        public bool AddBodyHashesToRawRequests { get; set; }

        public bool CallbackMustBeConfirmed { get; set; }

        public Uri? CallbackUri { get; set; }

        public IOAuthConsumerContext ConsumerContext { get; set; }

        public IConsumerRequestFactory ConsumerRequestFactory
        {
            get
            {
                return this.consumerRequestFactory;
            }

            set
            {
                ArgumentNullException.ThrowIfNull ( value );

                this.consumerRequestFactory = value;
            }
        }

        public Uri? ProxyServerUri { get; set; }

        public Uri? RequestTokenUri { get; set; }

        public Action<string>? ResponseBodyAction { get; set; }

        public Uri? UserAuthorizeUri { get; set; }

        public IConsumerRequest BuildAccessTokenContext ( string method , string xAuthMode , string xAuthUsername , string xAuthPassword )
        {
            ArgumentNullException.ThrowIfNull ( this.AccessTokenUri );

            return this.Request ( )
              .ForMethod ( method )
              .AlterContext ( context => context.XAuthUsername = xAuthUsername )
              .AlterContext ( context => context.XAuthPassword = xAuthPassword )
              .AlterContext ( context => context.XAuthMode = xAuthMode )
              .ForUri ( this.AccessTokenUri )
              .SignWithoutToken ( );
        }

        public IConsumerRequest BuildExchangeRequestTokenForAccessTokenContext ( IToken requestToken , string method , string? verificationCode )
        {
            ArgumentNullException.ThrowIfNull ( this.AccessTokenUri );

            return this.Request ( )
                .ForMethod ( method )
                .AlterContext ( context => context.Verifier = verificationCode )
                .ForUri ( this.AccessTokenUri )
                .SignWithToken ( requestToken );
        }

        public IConsumerRequest BuildRenewAccessTokenContext ( IToken requestToken , string method , string sessionHandle )
        {
            ArgumentNullException.ThrowIfNull ( this.AccessTokenUri );

            return this.Request ( )
                .ForMethod ( method )
                .AlterContext ( context => context.SessionHandle = sessionHandle )
                .ForUri ( this.AccessTokenUri )
                .SignWithToken ( requestToken );
        }

        public IConsumerRequest BuildRequestTokenContext ( string method )
        {
            ArgumentNullException.ThrowIfNull ( this.RequestTokenUri );

            return this.Request ( )
                .ForMethod ( method )
                .AlterContext ( context => context.CallbackUrl = ( this.CallbackUri == null ) ? "oob" : this.CallbackUri.ToString ( ) )
                .AlterContext ( context => context.Token = null )
                .ForUri ( this.RequestTokenUri )
                .SignWithoutToken ( );
        }

        public IOAuthSession EnableOAuthRequestBodyHashes ( )
        {
            this.AddBodyHashesToRawRequests = true;
            return this;
        }

        public async Task<IToken> ExchangeRequestTokenForAccessTokenAsync ( IToken requestToken , string verificationCode )
        {
            return await this.ExchangeRequestTokenForAccessTokenAsync ( requestToken , "GET" , verificationCode );
        }

        public async Task<IToken> ExchangeRequestTokenForAccessTokenAsync ( IToken requestToken , string method , string? verificationCode )
        {
            var context = this.BuildExchangeRequestTokenForAccessTokenContext ( requestToken , method , verificationCode );

            var token = await context.SelectAsync ( collection =>
                new TokenBase
                {
                    ConsumerKey = requestToken.ConsumerKey ,
                    Token = ParseResponseParameter ( collection , Parameters.OAuth_Token ) ,
                    TokenSecret = ParseResponseParameter ( collection , Parameters.OAuth_Token_Secret ) ,
                    SessionHandle = ParseResponseParameter ( collection , Parameters.OAuth_Session_Handle )
                } );

            this.AccessToken = token;

            return token;
        }

        public async Task<IToken> ExchangeRequestTokenForAccessTokenAsync ( IToken requestToken )
        {
            return await this.ExchangeRequestTokenForAccessTokenAsync ( requestToken , "GET" , null );
        }

        public async Task<IToken> GetAccessTokenUsingXAuthAsync ( string authMode , string username , string password )
        {
            var context = this.BuildAccessTokenContext ( "GET" , authMode , username , password );

            var token = await context.SelectAsync ( collection =>
                new TokenBase
                {
                    ConsumerKey = this.ConsumerContext.ConsumerKey ,
                    Token = ParseResponseParameter ( collection , Parameters.OAuth_Token ) ,
                    TokenSecret = ParseResponseParameter ( collection , Parameters.OAuth_Token_Secret ) ,
                    SessionHandle = ParseResponseParameter ( collection , Parameters.OAuth_Session_Handle )
                } );

            this.AccessToken = token;

            return token;
        }

        public async Task<IToken> GetRequestTokenAsync ( string method )
        {
            var context = this.BuildRequestTokenContext ( method );

            var results = await context.SelectAsync ( collection =>
                new
                {
                    this.ConsumerContext.ConsumerKey ,
                    Token = ParseResponseParameter ( collection , Parameters.OAuth_Token ) ,
                    TokenSecret = ParseResponseParameter ( collection , Parameters.OAuth_Token_Secret ) ,
                    CallackConfirmed = WasCallbackConfimed ( collection )
                } );

            return !results.CallackConfirmed && this.CallbackMustBeConfirmed
                ? throw Error.CallbackWasNotConfirmed ( )
                : ( IToken ) new TokenBase
                {
                    ConsumerKey = results.ConsumerKey ,
                    Token = results.Token ,
                    TokenSecret = results.TokenSecret
                };
        }

        public async Task<IToken> GetRequestTokenAsync ( )
        {
            return await this.GetRequestTokenAsync ( "GET" );
        }

        public string GetUserAuthorizationUrlForToken ( IToken token )
        {
            return this.GetUserAuthorizationUrlForToken ( token , null );
        }

        public string GetUserAuthorizationUrlForToken ( IToken token , string? callbackUrl )
        {
            ArgumentNullException.ThrowIfNull ( this.UserAuthorizeUri );

            var builder = new UriBuilder ( this.UserAuthorizeUri );

            NameValueCollection collection = [ ];

            if ( builder.Query != null )
            {
                collection.Add ( HttpUtility.ParseQueryString ( builder.Query ) );
            }

            if ( this.queryParameters != null )
            {
                collection.Add ( this.queryParameters );
            }

            collection [ Parameters.OAuth_Token ] = token.Token;

            if ( !string.IsNullOrEmpty ( callbackUrl ) )
            {
                collection [ Parameters.OAuth_Callback ] = callbackUrl;
            }

            builder.Query = "";

            return builder.Uri + "?" + UriUtility.FormatQueryString ( collection );
        }

        public async Task<IToken> RenewAccessTokenAsync ( IToken accessToken , string sessionHandle )
        {
            return await this.RenewAccessTokenAsync ( accessToken , "GET" , sessionHandle );
        }

        public async Task<IToken> RenewAccessTokenAsync ( IToken accessToken , string method , string sessionHandle )
        {
            var context = this.BuildRenewAccessTokenContext ( accessToken , method , sessionHandle );

            var token = await context.SelectAsync ( collection =>
                new TokenBase
                {
                    ConsumerKey = accessToken.ConsumerKey ,
                    Token = ParseResponseParameter ( collection , Parameters.OAuth_Token ) ,
                    TokenSecret = ParseResponseParameter ( collection , Parameters.OAuth_Token_Secret ) ,
                    SessionHandle = ParseResponseParameter ( collection , Parameters.OAuth_Session_Handle )
                } );

            this.AccessToken = token;

            return token;
        }

        public IConsumerRequest Request ( IToken accessToken )
        {
            var context = new OAuthContext
            {
                UseAuthorizationHeader = this.ConsumerContext.UseHeaderForOAuthParameters ,
                IncludeOAuthRequestBodyHashInSignature = this.AddBodyHashesToRawRequests
            };

            context.Cookies.Add ( this.cookies );
            context.FormEncodedParameters.Add ( this.formParameters );
            context.Headers.Add ( this.headers );
            context.QueryParameters.Add ( this.queryParameters );

            var consumerRequest = this.consumerRequestFactory.CreateConsumerRequest ( context , this.ConsumerContext , accessToken );

            consumerRequest.ProxyServerUri = this.ProxyServerUri;
            consumerRequest.ResponseBodyAction = this.ResponseBodyAction;

            return consumerRequest;
        }

        public IConsumerRequest Request ( )
        {
            var context = new OAuthContext
            {
                UseAuthorizationHeader = this.ConsumerContext.UseHeaderForOAuthParameters ,
                IncludeOAuthRequestBodyHashInSignature = this.AddBodyHashesToRawRequests
            };

            context.Cookies.Add ( this.cookies );
            context.FormEncodedParameters.Add ( this.formParameters );
            context.Headers.Add ( this.headers );
            context.QueryParameters.Add ( this.queryParameters );

            var consumerRequest = this.consumerRequestFactory.CreateConsumerRequest ( context , this.ConsumerContext , this.AccessToken );

            consumerRequest.ProxyServerUri = this.ProxyServerUri;
            consumerRequest.ResponseBodyAction = this.ResponseBodyAction;

            return consumerRequest;
        }

        public IOAuthSession RequiresCallbackConfirmation ( )
        {
            this.CallbackMustBeConfirmed = true;
            return this;
        }

        public IOAuthSession WithCookies ( IDictionary dictionary )
        {
            return this.AddItems ( this.cookies , dictionary );
        }

        public IOAuthSession WithCookies ( object anonymousClass )
        {
            return this.AddItems ( this.cookies , anonymousClass );
        }

        public IOAuthSession WithFormParameters ( IDictionary dictionary )
        {
            return this.AddItems ( this.formParameters , dictionary );
        }

        public IOAuthSession WithFormParameters ( object anonymousClass )
        {
            return this.AddItems ( this.formParameters , anonymousClass );
        }

        public IOAuthSession WithHeaders ( IDictionary dictionary )
        {
            return this.AddItems ( this.headers , dictionary );
        }

        public IOAuthSession WithHeaders ( object anonymousClass )
        {
            return this.AddItems ( this.headers , anonymousClass );
        }

        public IOAuthSession WithQueryParameters ( IDictionary dictionary )
        {
            return this.AddItems ( this.queryParameters , dictionary );
        }

        public IOAuthSession WithQueryParameters ( object anonymousClass )
        {
            return this.AddItems ( this.queryParameters , anonymousClass );
        }

        private static Uri? ParseCallbackUri ( string? callBackUrl )
        {
            return string.IsNullOrEmpty ( callBackUrl )
                ? null
                : callBackUrl.Equals ( "oob" , StringComparison.InvariantCultureIgnoreCase ) ? null : new Uri ( callBackUrl );
        }

        private static string? ParseResponseParameter ( NameValueCollection collection , string parameter )
        {
            string value = ( collection [ parameter ] ?? "" ).Trim ( );
            return ( value.Length > 0 ) ? value : null;
        }

        private static bool WasCallbackConfimed ( NameValueCollection parameters )
        {
            string? value = ParseResponseParameter ( parameters , Parameters.OAuth_Callback_Confirmed );

            return value == "true";
        }

        private OAuthSession AddItems ( NameValueCollection destination , object anonymousClass )
        {
            return this.AddItems ( destination , new ReflectionBasedDictionaryAdapter ( anonymousClass ) );
        }

        private OAuthSession AddItems ( NameValueCollection destination , IDictionary additions )
        {
            foreach ( string parameter in additions.Keys )
            {
                destination [ parameter ] = Convert.ToString ( additions [ parameter ] );
            }

            return this;
        }
    }
}