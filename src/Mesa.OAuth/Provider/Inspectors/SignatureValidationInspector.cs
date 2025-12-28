namespace Mesa.OAuth.Provider.Inspectors
{
    using Mesa.OAuth.Framework;
    using Mesa.OAuth.Framework.Interfaces;
    using Mesa.OAuth.Framework.Signing;
    using Mesa.OAuth.Framework.Signing.Interfaces;
    using Mesa.OAuth.Provider.Inspectors.Interfaces;
    using Mesa.OAuth.Storage.Interfaces;

    public class SignatureValidationInspector : IContextInspector
    {
        private readonly IConsumerStore consumerStore;

        private readonly IOAuthContextSigner signer;

        public SignatureValidationInspector ( IConsumerStore consumerStore )
            : this ( consumerStore , new OAuthContextSigner ( ) )
        {
        }

        public SignatureValidationInspector ( IConsumerStore consumerStore , IOAuthContextSigner signer )
        {
            this.consumerStore = consumerStore;
            this.signer = signer;
        }

        public virtual void InspectContext ( ProviderPhase phase , IOAuthContext context )
        {
            var signingContext = this.CreateSignatureContextForConsumer ( context );

            if ( !this.signer.ValidateSignature ( context , signingContext ) )
            {
                throw Error.FailedToValidateSignature ( context );
            }
        }

        protected virtual SigningContext CreateSignatureContextForConsumer ( IOAuthContext context )
        {
            var signingContext = new SigningContext
            {
                ConsumerSecret = this.consumerStore.GetConsumerSecret ( context )
            };

            if ( this.SignatureMethodRequiresCertificate ( context.SignatureMethod ) )
            {
                signingContext.Algorithm = this.consumerStore.GetConsumerPublicKey ( context );
            }

            return signingContext;
        }

        protected virtual bool SignatureMethodRequiresCertificate ( string? signatureMethod )
        {
            return signatureMethod is not SignatureMethod.HmacSha1 and not SignatureMethod.PlainText;
        }
    }
}