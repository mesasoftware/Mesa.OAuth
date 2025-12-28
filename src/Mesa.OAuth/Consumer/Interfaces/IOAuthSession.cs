namespace Mesa.OAuth.Consumer.Interfaces
{
    using System;
    using System.Collections;
    using System.Threading.Tasks;
    using Mesa.OAuth.Framework.Interfaces;

    public interface IOAuthSession
    {
        IToken? AccessToken { get; set; }

        Uri? AccessTokenUri { get; set; }

        Uri? CallbackUri { get; set; }

        IOAuthConsumerContext ConsumerContext { get; set; }

        Uri? ProxyServerUri { get; set; }

        Uri? RequestTokenUri { get; set; }

        Action<string>? ResponseBodyAction { get; set; }

        Uri? UserAuthorizeUri { get; set; }

        IConsumerRequest BuildAccessTokenContext ( string method , string xAuthMode , string xAuthUsername , string xAuthPassword );

        IConsumerRequest BuildExchangeRequestTokenForAccessTokenContext ( IToken requestToken , string method , string? verificationCode );

        IConsumerRequest BuildRequestTokenContext ( string method );

        Task<IToken> ExchangeRequestTokenForAccessTokenAsync ( IToken requestToken , string verificationCode );

        Task<IToken> ExchangeRequestTokenForAccessTokenAsync ( IToken requestToken , string method , string verificationCode );

        Task<IToken> ExchangeRequestTokenForAccessTokenAsync ( IToken requestToken );

        Task<IToken> GetAccessTokenUsingXAuthAsync ( string authMode , string username , string password );

        Task<IToken> GetRequestTokenAsync ( string method );

        Task<IToken> GetRequestTokenAsync ( );

        string GetUserAuthorizationUrlForToken ( IToken token , string callbackUrl );

        string GetUserAuthorizationUrlForToken ( IToken token );

        IConsumerRequest Request ( );

        IConsumerRequest Request ( IToken accessToken );

        IOAuthSession RequiresCallbackConfirmation ( );

        IOAuthSession WithCookies ( IDictionary dictionary );

        IOAuthSession WithCookies ( object anonymousClass );

        IOAuthSession WithFormParameters ( IDictionary dictionary );

        IOAuthSession WithFormParameters ( object anonymousClass );

        IOAuthSession WithHeaders ( IDictionary dictionary );

        IOAuthSession WithHeaders ( object anonymousClass );

        IOAuthSession WithQueryParameters ( IDictionary dictionary );

        IOAuthSession WithQueryParameters ( object anonymousClass );
    }
}