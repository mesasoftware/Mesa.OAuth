namespace Mesa.OAuth.Consumer
{
    using System;
    using System.Security.Cryptography;
    using Mesa.OAuth.Consumer.Interfaces;
    using Mesa.OAuth.Framework;
    using Mesa.OAuth.Framework.Interfaces;
    using Mesa.OAuth.Framework.Signing;
    using Mesa.OAuth.Framework.Signing.Interfaces;
    using Mesa.OAuth.Utility;

    [Serializable]
    public class OAuthConsumerContext : IOAuthConsumerContext
    {
        private INonceGenerator nonceGenerator = new GuidNonceGenerator ( );

        private IOAuthContextSigner signer = new OAuthContextSigner ( );

        public OAuthConsumerContext ( )
        {
            this.SignatureMethod = Framework.SignatureMethod.PlainText;
        }

        public string? ConsumerKey { get; set; }

        public string? ConsumerSecret { get; set; }

        public AsymmetricAlgorithm? Key { get; set; }

        public INonceGenerator NonceGenerator
        {
            get { return this.nonceGenerator; }
            set { this.nonceGenerator = value; }
        }

        public string? Realm { get; set; }

        public string SignatureMethod { get; set; }

        public IOAuthContextSigner Signer
        {
            get { return this.signer; }
            set { this.signer = value; }
        }

        public bool UseHeaderForOAuthParameters { get; set; }

        public string? UserAgent { get; set; }

        public void SignContext ( IOAuthContext context )
        {
            this.EnsureStateIsValid ( );

            context.UseAuthorizationHeader = this.UseHeaderForOAuthParameters;
            context.Nonce = this.nonceGenerator.GenerateNonce ( context );
            context.ConsumerKey = this.ConsumerKey;
            context.Realm = this.Realm;
            context.SignatureMethod = this.SignatureMethod;
            context.Timestamp = Clock.EpochString;
            context.Version = "1.0";

            context.Nonce = this.NonceGenerator.GenerateNonce ( context );

            string signatureBase = context.GenerateSignatureBase ( );

            this.signer.SignContext ( context ,
                                new SigningContext
                                { Algorithm = this.Key , SignatureBase = signatureBase , ConsumerSecret = this.ConsumerSecret } );
        }

        public void SignContextWithToken ( IOAuthContext context , IToken token )
        {
            context.Token = token.Token;
            context.TokenSecret = token.TokenSecret;

            this.SignContext ( context );
        }

        private void EnsureStateIsValid ( )
        {
            if ( string.IsNullOrEmpty ( this.ConsumerKey ) )
            {
                throw Error.EmptyConsumerKey ( );
            }

            if ( string.IsNullOrEmpty ( this.SignatureMethod ) )
            {
                throw Error.UnknownSignatureMethod ( this.SignatureMethod );
            }

            if ( ( this.SignatureMethod == Framework.SignatureMethod.RsaSha1 )
                && ( this.Key == null ) )
            {
                throw Error.ForRsaSha1SignatureMethodYouMustSupplyAssymetricKeyParameter ( );
            }
        }
    }
}