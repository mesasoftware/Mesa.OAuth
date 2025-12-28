namespace Mesa.OAuth.Storage.Interfaces
{
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Mesa.OAuth.Framework.Interfaces;

    public interface IConsumerStore
    {
        AsymmetricAlgorithm GetConsumerPublicKey ( IConsumer consumer );

        string GetConsumerSecret ( IOAuthContext consumer );

        bool IsConsumer ( IConsumer consumer );

        void SetConsumerCertificate ( IConsumer consumer , X509Certificate2 certificate );

        void SetConsumerSecret ( IConsumer consumer , string consumerSecret );
    }
}