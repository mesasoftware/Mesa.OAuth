namespace Mesa.OAuth.Framework.Interfaces
{
    using System;
    using System.Collections.Specialized;

    public interface IOAuthContext : IToken
    {
        NameValueCollection? AuthorizationHeaderParameters { get; set; }

        string? BodyHash { get; set; }

        string? CallbackUrl { get; set; }

        NameValueCollection Cookies { get; set; }

        NameValueCollection FormEncodedParameters { get; set; }

        NameValueCollection Headers { get; set; }

        bool IncludeOAuthRequestBodyHashInSignature { get; set; }

        string? Nonce { get; set; }

        string? NormalizedRequestUrl { get; }

        NameValueCollection QueryParameters { get; set; }

        byte [ ]? RawContent { get; set; }

        string? RawContentType { get; set; }

        Uri? RawUri { get; set; }

        string? RequestMethod { get; set; }

        string? Signature { get; set; }

        string? SignatureMethod { get; set; }

        string? Timestamp { get; set; }

        bool UseAuthorizationHeader { get; set; }

        string? Verifier { get; set; }

        string? Version { get; set; }

        string? XAuthMode { get; set; }

        string? XAuthPassword { get; set; }

        string? XAuthUsername { get; set; }

        void GenerateAndSetBodyHash ( );

        string GenerateBodyHash ( );

        string GenerateOAuthParametersForHeader ( );

        string GenerateSignatureBase ( );

        Uri GenerateUri ( );

        Uri GenerateUriWithoutOAuthParameters ( );

        string GenerateUrl ( );

        string? ToString ( );
    }
}