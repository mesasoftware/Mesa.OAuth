namespace Mesa.OAuth.Framework.Signing
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    using Mesa.OAuth.Framework.Interfaces;
    using Mesa.OAuth.Framework.Signing.Interfaces;

    public class RsaSha1SignatureImplementation : IContextSignatureImplementation
    {
        public string MethodName
        {
            get { return SignatureMethod.RsaSha1; }
        }

        public void SignContext ( IOAuthContext authContext , SigningContext signingContext )
        {
            authContext.Signature = GenerateSignature ( signingContext );
        }

        public bool ValidateSignature ( IOAuthContext? authContext , SigningContext? signingContext )
        {
            ArgumentNullException.ThrowIfNull ( authContext );
            ArgumentNullException.ThrowIfNull ( signingContext );
            ArgumentException.ThrowIfNullOrWhiteSpace ( authContext.Signature );
            ArgumentException.ThrowIfNullOrWhiteSpace ( signingContext.SignatureBase );

            if ( signingContext.Algorithm == null )
            {
                throw Error.AlgorithmPropertyNotSetOnSigningContext ( );
            }

            var sha1 = GenerateHash ( signingContext );

            var deformatter = new RSAPKCS1SignatureDeformatter ( signingContext.Algorithm );
            deformatter.SetHashAlgorithm ( "MD5" );

            byte [ ] signature = Convert.FromBase64String ( authContext.Signature );

            return deformatter.VerifySignature ( sha1 , signature );
        }

        private static SHA1 GenerateHash ( SigningContext signingContext )
        {
            ArgumentException.ThrowIfNullOrWhiteSpace ( signingContext.SignatureBase );

            var sha1 = SHA1.Create ( );

            byte [ ] dataBuffer = Encoding.ASCII.GetBytes ( signingContext.SignatureBase );

            var cs = new CryptoStream ( Stream.Null , sha1 , CryptoStreamMode.Write );
            cs.Write ( dataBuffer , 0 , dataBuffer.Length );
            cs.Close ( );

            return sha1;
        }

        private static string GenerateSignature ( SigningContext signingContext )
        {
            if ( signingContext.Algorithm == null )
            {
                throw Error.AlgorithmPropertyNotSetOnSigningContext ( );
            }

            var sha1 = GenerateHash ( signingContext );

            var formatter = new RSAPKCS1SignatureFormatter ( signingContext.Algorithm );
            formatter.SetHashAlgorithm ( "MD5" );

            byte [ ] signature = formatter.CreateSignature ( sha1 );

            return Convert.ToBase64String ( signature );
        }
    }
}