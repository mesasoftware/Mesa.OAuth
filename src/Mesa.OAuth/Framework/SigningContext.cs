namespace Mesa.OAuth.Framework
{
    using System.Security.Cryptography;

    public class SigningContext
    {
        public AsymmetricAlgorithm? Algorithm { get; set; }

        public string? ConsumerSecret { get; set; }

        public string? SignatureBase { get; set; }
    }
}