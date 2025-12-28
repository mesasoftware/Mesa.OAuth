namespace Mesa.OAuth.Framework.Signing
{
    using System;
    using Mesa.OAuth.Framework.Interfaces;
    using Mesa.OAuth.Framework.Signing.Interfaces;
    using Mesa.OAuth.Utility;

    public class PlainTextSignatureImplementation : IContextSignatureImplementation
    {
        public string MethodName
        {
            get { return SignatureMethod.PlainText; }
        }

        public void SignContext ( IOAuthContext authContext , SigningContext signingContext )
        {
            authContext.Signature = GenerateSignature ( authContext , signingContext );
        }

        public bool ValidateSignature ( IOAuthContext? authContext , SigningContext? signingContext )
        {
            ArgumentNullException.ThrowIfNull ( authContext );
            ArgumentNullException.ThrowIfNull ( signingContext );
            ArgumentException.ThrowIfNullOrWhiteSpace ( authContext.Signature );
            ArgumentException.ThrowIfNullOrWhiteSpace ( signingContext.SignatureBase );

            return authContext.Signature.EqualsInConstantTime ( GenerateSignature ( authContext , signingContext ) );
        }

        private static string GenerateSignature ( IOAuthContext authContext , SigningContext signingContext )
        {
            return UriUtility.UrlEncode ( string.Format ( "{0}&{1}" , signingContext.ConsumerSecret , authContext.TokenSecret ) );
        }
    }
}