namespace Mesa.OAuth.Consumer.Interfaces
{
    using System.Security.Cryptography;
    using Mesa.OAuth.Framework.Interfaces;

    /// <summary>
    /// A consumer context is used to identify a consumer, and to sign a context on behalf
    /// of a consumer using an optional supplied token.
    /// </summary>
    public interface IOAuthConsumerContext
    {
        string? ConsumerKey { get; set; }

        string? ConsumerSecret { get; set; }

        AsymmetricAlgorithm? Key { get; set; }

        string? Realm { get; set; }

        string SignatureMethod { get; set; }

        bool UseHeaderForOAuthParameters { get; set; }

        string? UserAgent { get; set; }

        void SignContext ( IOAuthContext context );

        void SignContextWithToken ( IOAuthContext context , IToken token );
    }
}