namespace Mesa.OAuth.Provider.Inspectors
{
    public enum ProviderPhase
    {
        GrantRequestToken,

        ExchangeRequestTokenForAccessToken,

        AccessProtectedResourceRequest,

        RenewAccessToken,

        CreateAccessToken
    }
}