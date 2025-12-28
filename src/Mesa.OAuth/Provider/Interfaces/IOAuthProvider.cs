namespace Mesa.OAuth.Provider.Interfaces
{
    using Mesa.OAuth.Framework.Interfaces;

    public interface IOAuthProvider
    {
        void AccessProtectedResourceRequest ( IOAuthContext context );

        IToken CreateAccessToken ( IOAuthContext context );

        IToken? ExchangeRequestTokenForAccessToken ( IOAuthContext context );

        IToken GrantRequestToken ( IOAuthContext context );

        IToken RenewAccessToken ( IOAuthContext context );
    }
}