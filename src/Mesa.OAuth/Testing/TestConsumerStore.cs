namespace Mesa.OAuth.Testing
{
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Mesa.OAuth.Framework.Interfaces;
    using Mesa.OAuth.Storage.Interfaces;

    public class TestConsumerStore : IConsumerStore
    {
        public AsymmetricAlgorithm GetConsumerPublicKey ( IConsumer consumer )
        {
            var publicKey = TestCertificates.OAuthTestCertificate ( ).GetRSAPublicKey ( );

            ArgumentNullException.ThrowIfNull ( publicKey );

            return publicKey;
        }

        public string GetConsumerSecret ( IOAuthContext consumer )
        {
            return "secret";
        }

        public bool IsConsumer ( IConsumer consumer )
        {
            return consumer.ConsumerKey == "key" && string.IsNullOrEmpty ( consumer.Realm );
        }

        public void SetConsumerCertificate ( IConsumer consumer , X509Certificate2 certificate )
        {
            throw new NotImplementedException ( );
        }

        public void SetConsumerSecret ( IConsumer consumer , string consumerSecret )
        {
            throw new NotImplementedException ( );
        }
    }
}