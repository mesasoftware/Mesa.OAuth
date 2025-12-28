namespace Mesa.OAuth.Consumer
{
    using System.Security.Cryptography.X509Certificates;
    using Mesa.OAuth.Consumer.Interfaces;

    public class NullCertificateFactory : ICertificateFactory
    {
        public X509Certificate2? CreateCertificate ( )
        {
            return null;
        }

        public int GetMatchingCertificateCount ( )
        {
            return 0;
        }
    }
}