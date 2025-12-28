namespace Mesa.OAuth.Framework.Signing
{
    using System;
    using System.Security.Cryptography;
    using System.Text;
    using Mesa.OAuth.Framework.Interfaces;
    using Mesa.OAuth.Framework.Signing.Interfaces;
    using Mesa.OAuth.Utility;

    public class HmacSha1SignatureImplementation : IContextSignatureImplementation
    {
        public string MethodName
        {
            get { return SignatureMethod.HmacSha1; }
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

        private static string ComputeHash ( HashAlgorithm hashAlgorithm , string? data )
        {
            ArgumentNullException.ThrowIfNull ( hashAlgorithm );
            ArgumentException.ThrowIfNullOrWhiteSpace ( data );

            byte [ ] dataBuffer = Encoding.ASCII.GetBytes ( data );
            byte [ ] hashBytes = hashAlgorithm.ComputeHash ( dataBuffer );

            return Convert.ToBase64String ( hashBytes );
        }

        private static string GenerateSignature ( IToken authContext , SigningContext signingContext )
        {
            string consumerSecret = ( signingContext.ConsumerSecret != null )
                                        ? UriUtility.UrlEncode ( signingContext.ConsumerSecret )
                                        : "";
            string? tokenSecret = ( authContext.TokenSecret != null )
                                ? UriUtility.UrlEncode ( authContext.TokenSecret )
                                : null;

            string hashSource = string.Format ( "{0}&{1}" , consumerSecret , tokenSecret );

            var hashAlgorithm = new HMACSHA1 { Key = Encoding.ASCII.GetBytes ( hashSource ) };

            return ComputeHash ( hashAlgorithm , signingContext.SignatureBase );
        }
    }
}