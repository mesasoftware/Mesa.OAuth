namespace Mesa.OAuth.Framework
{
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using Mesa.OAuth.KeyInterop;

    public static class CertificateUtility
    {
        /// <summary>
        /// Loads a certificate given both it's private and public keys - generally used to
        /// load keys provided on the OAuth wiki's for verification of implementation correctness.
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="certificate"></param>
        /// <returns></returns>
        public static X509Certificate2 LoadCertificateFromStrings ( string privateKey , string certificate )
        {
            var parser = new AsnKeyParser ( Convert.FromBase64String ( privateKey ) );
            var parameters = parser.ParseRSAPrivateKey ( );
#if NET8_0
            var x509 = new X509Certificate2 ( Encoding.ASCII.GetBytes ( certificate ) );
#else
            var x509 = X509CertificateLoader.LoadCertificate ( Encoding.ASCII.GetBytes ( certificate ) );
#endif
            var provider = new RSACryptoServiceProvider ( );
            provider.ImportParameters ( parameters );

            return x509.CopyWithPrivateKey ( provider );
        }
    }
}