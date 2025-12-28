namespace Mesa.OAuth.Framework
{
    using System;
    using Mesa.OAuth.Framework.Interfaces;

    [Serializable]
    public class TokenBase : IToken
    {
        public string? ConsumerKey { get; set; }

        public string? Realm { get; set; }

        public string? SessionHandle { get; set; }

        public string? Token { get; set; }

        public string? TokenSecret { get; set; }

        public override string ToString ( )
        {
            return UriUtility.FormatTokenForResponse ( this );
        }
    }
}