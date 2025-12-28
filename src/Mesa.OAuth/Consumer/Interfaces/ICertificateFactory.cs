namespace Mesa.OAuth.Consumer.Interfaces
{
    using System.Security.Cryptography.X509Certificates;

    public interface ICertificateFactory
    {
        X509Certificate2? CreateCertificate ( );

        int GetMatchingCertificateCount ( );
    }
}