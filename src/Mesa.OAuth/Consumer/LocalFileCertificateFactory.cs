namespace Mesa.OAuth.Consumer
{
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Mesa.OAuth.Consumer.Interfaces;

    public class LocalFileCertificateFactory : ICertificateFactory
    {
        private readonly string filename;

        private readonly string password;

        /// <summary>
        /// Initializes a new instance of the <see cref="LocalFileCertificateFactory"/> class.
        /// </summary>
        /// <param name="filename">The filename.</param>
        /// <param name="password">The password.</param>
        public LocalFileCertificateFactory ( string filename , string password )
        {
            this.filename = filename;
            this.password = password;

            if ( !File.Exists ( filename ) )
            {
                throw new FileNotFoundException ( "The certificate file could not be located on disk." , filename );
            }

            if ( this.CreateCertificate ( ) == null )
            {
                throw new ApplicationException ( "The certificate could not be loaded from disk." );
            }
        }

        /// <summary>
        /// Creates the certificate.
        /// </summary>
        /// <returns></returns>
        public X509Certificate2? CreateCertificate ( )
        {
            if ( !File.Exists ( this.filename ) )
            {
                return null;
            }

            try
            {
#if NET8_0
                var certificate = new X509Certificate2 ( this.filename , this.password );
#else
                var certificate = X509CertificateLoader.LoadCertificateFromFile ( this.filename );
#endif
                Debug.Assert ( certificate.Subject != string.Empty );
                return certificate;
            }
            catch ( CryptographicException )
            {
                return null;
            }
        }

        /// <summary>
        /// Counts the matching certificates.
        /// </summary>
        /// <returns></returns>
        public int GetMatchingCertificateCount ( )
        {
            return this.CreateCertificate ( ) != null ? 1 : 0;
        }
    }
}