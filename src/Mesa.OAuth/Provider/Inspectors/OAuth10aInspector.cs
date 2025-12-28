namespace Mesa.OAuth.Provider.Inspectors
{
    using System;
    using Mesa.OAuth.Framework;
    using Mesa.OAuth.Framework.Interfaces;
    using Mesa.OAuth.Provider.Inspectors.Interfaces;
    using Mesa.OAuth.Storage.Interfaces;

    /// <summary>
    /// This inspector implements additional behavior required by the 1.0a version of OAuth.
    /// </summary>
    public class OAuth10AInspector : IContextInspector
    {
        private readonly ITokenStore tokenStore;

        public OAuth10AInspector ( ITokenStore tokenStore )
        {
            ArgumentNullException.ThrowIfNull ( tokenStore );

            this.tokenStore = tokenStore;
        }

        public void InspectContext ( ProviderPhase phase , IOAuthContext context )
        {
            if ( phase == ProviderPhase.GrantRequestToken )
            {
                ValidateCallbackUrlIsPartOfRequest ( context );
            }
            else if ( phase == ProviderPhase.ExchangeRequestTokenForAccessToken )
            {
                this.ValidateVerifierMatchesStoredVerifier ( context );
            }
        }

        private static void ValidateCallbackUrlIsPartOfRequest ( IOAuthContext context )
        {
            if ( string.IsNullOrEmpty ( context.CallbackUrl ) )
            {
                throw Error.MissingRequiredOAuthParameter ( context , Parameters.OAuth_Callback );
            }
        }

        private void ValidateVerifierMatchesStoredVerifier ( IOAuthContext context )
        {
            string? actual = context.Verifier;

            if ( string.IsNullOrEmpty ( actual ) )
            {
                throw Error.MissingRequiredOAuthParameter ( context , Parameters.OAuth_Verifier );
            }

            string? expected = this.tokenStore.GetVerificationCodeForRequestToken ( context );

            if ( expected != actual.Trim ( ) )
            {
                throw Error.RejectedRequiredOAuthParameter ( context , Parameters.OAuth_Verifier );
            }
        }
    }
}