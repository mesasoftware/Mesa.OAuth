namespace Mesa.OAuth.Provider
{
    using System;
    using System.Collections.Generic;
    using Mesa.OAuth.Framework;
    using Mesa.OAuth.Framework.Interfaces;
    using Mesa.OAuth.Provider.Inspectors;
    using Mesa.OAuth.Provider.Inspectors.Interfaces;
    using Mesa.OAuth.Provider.Interfaces;
    using Mesa.OAuth.Storage;
    using Mesa.OAuth.Storage.Interfaces;

    public class OAuthProvider : IOAuthProvider
    {
        private readonly List<IContextInspector> inspectors = [ ];

        private readonly ITokenStore tokenStore;

        public OAuthProvider ( ITokenStore tokenStore , params IContextInspector [ ] inspectors )
        {
            this.RequiresCallbackUrlInRequest = true;

            ArgumentNullException.ThrowIfNull ( tokenStore );

            this.tokenStore = tokenStore;

            if ( inspectors != null )
            {
                this.inspectors.AddRange ( inspectors );
            }
        }

        public bool RequiresCallbackUrlInRequest { get; set; }

        public virtual void AccessProtectedResourceRequest ( IOAuthContext context )
        {
            this.InspectRequest ( ProviderPhase.AccessProtectedResourceRequest , context );

            this.tokenStore.ConsumeAccessToken ( context );
        }

        public void AddInspector ( IContextInspector inspector )
        {
            this.inspectors.Add ( inspector );
        }

        public IToken CreateAccessToken ( IOAuthContext context )
        {
            this.InspectRequest ( ProviderPhase.CreateAccessToken , context );

            return this.tokenStore.CreateAccessToken ( context );
        }

        public virtual IToken? ExchangeRequestTokenForAccessToken ( IOAuthContext context )
        {
            this.InspectRequest ( ProviderPhase.ExchangeRequestTokenForAccessToken , context );

            this.tokenStore.ConsumeRequestToken ( context );

            switch ( this.tokenStore.GetStatusOfRequestForAccess ( context ) )
            {
                case RequestForAccessStatus.Granted:
                    break;

                case RequestForAccessStatus.Unknown:
                    throw Error.ConsumerHasNotBeenGrantedAccessYet ( context );
                default:
                    throw Error.ConsumerHasBeenDeniedAccess ( context );
            }

            return this.tokenStore.GetAccessTokenAssociatedWithRequestToken ( context );
        }

        public virtual IToken GrantRequestToken ( IOAuthContext context )
        {
            AssertContextDoesNotIncludeToken ( context );

            this.InspectRequest ( ProviderPhase.GrantRequestToken , context );

            return this.tokenStore.CreateRequestToken ( context );
        }

        public IToken RenewAccessToken ( IOAuthContext context )
        {
            this.InspectRequest ( ProviderPhase.RenewAccessToken , context );

            return this.tokenStore.RenewAccessToken ( context );
        }

        protected virtual void InspectRequest ( ProviderPhase phase , IOAuthContext context )
        {
            AssertContextDoesNotIncludeTokenSecret ( context );

            this.AddStoredTokenSecretToContext ( context , phase );

            this.ApplyInspectors ( context , phase );
        }

        private static void AssertContextDoesNotIncludeToken ( IOAuthContext context )
        {
            if ( context.Token != null )
            {
                throw Error.RequestForTokenMustNotIncludeTokenInContext ( context );
            }
        }

        private static void AssertContextDoesNotIncludeTokenSecret ( IOAuthContext context )
        {
            if ( !string.IsNullOrEmpty ( context.TokenSecret ) )
            {
                throw new OAuthException ( context , OAuthProblems.ParameterRejected , "The oauth_token_secret must not be transmitted to the provider." );
            }
        }

        private void AddStoredTokenSecretToContext ( IOAuthContext context , ProviderPhase phase )
        {
            if ( phase == ProviderPhase.ExchangeRequestTokenForAccessToken )
            {
                string? secret = this.tokenStore.GetRequestTokenSecret ( context );

                context.TokenSecret = secret;
            }
            else if ( phase is ProviderPhase.AccessProtectedResourceRequest or ProviderPhase.RenewAccessToken )
            {
                string? secret = this.tokenStore.GetAccessTokenSecret ( context );

                context.TokenSecret = secret;
            }
        }

        private void ApplyInspectors ( IOAuthContext context , ProviderPhase phase )
        {
            foreach ( var inspector in this.inspectors )
            {
                inspector.InspectContext ( phase , context );
            }
        }
    }
}