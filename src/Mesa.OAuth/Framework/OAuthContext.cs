namespace Mesa.OAuth.Framework
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Specialized;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Web;
    using Mesa.OAuth.Framework.Interfaces;
    using QueryParameter = System.Collections.Generic.KeyValuePair<string , string>;

    [Serializable]
    public class OAuthContext : IOAuthContext
    {
        private readonly BoundParameter bodyHash;

        private readonly BoundParameter callbackUrl;

        private readonly BoundParameter consumerKey;

        private readonly BoundParameter nonce;

        private readonly BoundParameter sessionHandle;

        private readonly BoundParameter signature;

        private readonly BoundParameter signatureMethod;

        private readonly BoundParameter timestamp;

        private readonly BoundParameter token;

        private readonly BoundParameter tokenSecret;

        private readonly BoundParameter verifier;

        private readonly BoundParameter version;

        private readonly BoundParameter xAuthMode;

        private readonly BoundParameter xAuthPassword;

        private readonly BoundParameter xAuthUsername;

        private NameValueCollection? authorizationHeaderParameters;

        private NameValueCollection? cookies;

        private NameValueCollection? formEncodedParameters;

        private NameValueCollection? headers;

        private string? normalizedRequestUrl;

        private NameValueCollection? queryParameters;

        private Uri? rawUri;

        public OAuthContext ( )
        {
            this.verifier = new BoundParameter ( Parameters.OAuth_Verifier , this );
            this.consumerKey = new BoundParameter ( Parameters.OAuth_Consumer_Key , this );
            this.callbackUrl = new BoundParameter ( Parameters.OAuth_Callback , this );
            this.nonce = new BoundParameter ( Parameters.OAuth_Nonce , this );
            this.signature = new BoundParameter ( Parameters.OAuth_Signature , this );
            this.signatureMethod = new BoundParameter ( Parameters.OAuth_Signature_Method , this );
            this.timestamp = new BoundParameter ( Parameters.OAuth_Timestamp , this );
            this.token = new BoundParameter ( Parameters.OAuth_Token , this );
            this.tokenSecret = new BoundParameter ( Parameters.OAuth_Token_Secret , this );
            this.version = new BoundParameter ( Parameters.OAuth_Version , this );
            this.sessionHandle = new BoundParameter ( Parameters.OAuth_Session_Handle , this );
            this.bodyHash = new BoundParameter ( Parameters.OAuth_Body_Hash , this );

            this.xAuthUsername = new BoundParameter ( Parameters.XAuthUsername , this );
            this.xAuthPassword = new BoundParameter ( Parameters.XAuthPassword , this );
            this.xAuthMode = new BoundParameter ( Parameters.XAuthMode , this );

            this.FormEncodedParameters = [ ];
            this.Cookies = [ ];
            this.Headers = [ ];
            this.AuthorizationHeaderParameters = [ ];
        }

        public NameValueCollection? AuthorizationHeaderParameters
        {
            get
            {
                this.authorizationHeaderParameters ??= [ ];

                return this.authorizationHeaderParameters;
            }

            set
            {
                this.authorizationHeaderParameters = value;
            }
        }

        public string? BodyHash
        {
            get { return this.bodyHash.Value; }
            set { this.bodyHash.Value = value; }
        }

        public string? CallbackUrl
        {
            get { return this.callbackUrl.Value; }
            set { this.callbackUrl.Value = value; }
        }

        public string? ConsumerKey
        {
            get { return this.consumerKey.Value; }
            set { this.consumerKey.Value = value; }
        }

        public NameValueCollection Cookies
        {
            get
            {
                this.cookies ??= [ ];

                return this.cookies;
            }

            set
            {
                this.cookies = value;
            }
        }

        public NameValueCollection FormEncodedParameters
        {
            get
            {
                this.formEncodedParameters ??= [ ];

                return this.formEncodedParameters;
            }

            set
            {
                this.formEncodedParameters = value;
            }
        }

        public NameValueCollection Headers
        {
            get
            {
                this.headers ??= [ ];

                return this.headers;
            }

            set
            {
                this.headers = value;
            }
        }

        public bool IncludeOAuthRequestBodyHashInSignature { get; set; }

        public string? Nonce
        {
            get { return this.nonce.Value; }
            set { this.nonce.Value = value; }
        }

        public string? NormalizedRequestUrl
        {
            get { return this.normalizedRequestUrl; }
        }

        public NameValueCollection QueryParameters
        {
            get
            {
                this.queryParameters ??= [ ];

                return this.queryParameters;
            }

            set
            {
                this.queryParameters = value;
            }
        }

        public byte [ ]? RawContent { get; set; }

        public string? RawContentType { get; set; }

        public Uri? RawUri
        {
            get
            {
                return this.rawUri;
            }

            set
            {
                this.rawUri = value;

                var newParameters = HttpUtility.ParseQueryString ( this.rawUri?.Query ?? string.Empty );

                // TODO: tidy this up, bit clunky

                foreach ( string parameter in newParameters )
                {
                    this.QueryParameters [ parameter ] = newParameters [ parameter ];
                }

                this.normalizedRequestUrl = this.rawUri != null ? UriUtility.NormalizeUri ( this.rawUri ) : string.Empty;
            }
        }

        public string? Realm
        {
            get
            {
                return this.AuthorizationHeaderParameters? [ Parameters.Realm ];
            }

            set
            {
                this.AuthorizationHeaderParameters ??= [ ];

                this.AuthorizationHeaderParameters [ Parameters.Realm ] = value;
            }
        }

        public string? RequestMethod { get; set; }

        public string? SessionHandle
        {
            get { return this.sessionHandle.Value; }
            set { this.sessionHandle.Value = value; }
        }

        public string? Signature
        {
            get { return this.signature.Value; }
            set { this.signature.Value = value; }
        }

        public string? SignatureMethod
        {
            get { return this.signatureMethod.Value; }
            set { this.signatureMethod.Value = value; }
        }

        public string? Timestamp
        {
            get { return this.timestamp.Value; }
            set { this.timestamp.Value = value; }
        }

        public string? Token
        {
            get { return this.token.Value; }
            set { this.token.Value = value; }
        }

        public string? TokenSecret
        {
            get { return this.tokenSecret.Value; }
            set { this.tokenSecret.Value = value; }
        }

        public bool UseAuthorizationHeader { get; set; }

        public string? Verifier
        {
            get { return this.verifier.Value; }
            set { this.verifier.Value = value; }
        }

        public string? Version
        {
            get { return this.version.Value; }
            set { this.version.Value = value; }
        }

        public string? XAuthMode
        {
            get { return this.xAuthMode.Value; }
            set { this.xAuthMode.Value = value; }
        }

        public string? XAuthPassword
        {
            get { return this.xAuthPassword.Value; }
            set { this.xAuthPassword.Value = value; }
        }

        public string? XAuthUsername
        {
            get { return this.xAuthUsername.Value; }
            set { this.xAuthUsername.Value = value; }
        }

        public void GenerateAndSetBodyHash ( )
        {
            this.BodyHash = this.GenerateBodyHash ( );
        }

        public string GenerateBodyHash ( )
        {
            byte [ ] hash = SHA1.HashData ( this.RawContent ?? Array.Empty<byte> ( ) );
            return Convert.ToBase64String ( hash );
        }

        public string GenerateOAuthParametersForHeader ( )
        {
            var builder = new StringBuilder ( );

            if ( this.Realm != null )
            {
                builder.Append ( "realm=\"" ).Append ( this.Realm ).Append ( '"' );
            }

            var parameters = this.AuthorizationHeaderParameters?.ToQueryParametersExcludingTokenSecret ( );

            if ( parameters != null )
            {
                foreach ( var parameter in parameters.Where ( p => p.Key != Parameters.Realm ) )
                {
                    if ( builder.Length > 0 )
                    {
                        builder.Append ( ',' );
                    }

                    builder.Append ( UriUtility.UrlEncode ( parameter.Key ) ).Append ( "=\"" ).Append (
                        UriUtility.UrlEncode ( parameter.Value ) ).Append ( '"' );
                }
            }

            builder.Insert ( 0 , "OAuth " );

            return builder.ToString ( );
        }

        public string GenerateSignatureBase ( )
        {
            if ( string.IsNullOrEmpty ( this.ConsumerKey ) )
            {
                throw Error.MissingRequiredOAuthParameter ( this , Parameters.OAuth_Consumer_Key );
            }

            if ( string.IsNullOrEmpty ( this.SignatureMethod ) )
            {
                throw Error.MissingRequiredOAuthParameter ( this , Parameters.OAuth_Signature_Method );
            }

            if ( string.IsNullOrEmpty ( this.RequestMethod ) )
            {
                throw Error.RequestMethodHasNotBeenAssigned ( "RequestMethod" );
            }

            if ( this.IncludeOAuthRequestBodyHashInSignature )
            {
                this.GenerateAndSetBodyHash ( );
            }

            List<QueryParameter> allParameters = [ ];

            //fix for issue: http://groups.google.com/group/oauth/browse_thread/thread/42ef5fecc54a7e9a/a54e92b13888056c?hl=en&lnk=gst&q=Signing+PUT+Request#a54e92b13888056c
            if ( this.FormEncodedParameters != null && this.RequestMethod == "POST" )
            {
                allParameters.AddRange ( this.FormEncodedParameters.ToQueryParametersExcludingTokenSecret ( ) );
            }

            if ( this.QueryParameters != null )
            {
                allParameters.AddRange ( this.QueryParameters.ToQueryParametersExcludingTokenSecret ( ) );
            }

            if ( this.Cookies != null )
            {
                allParameters.AddRange ( this.Cookies.ToQueryParametersExcludingTokenSecret ( ) );
            }

            if ( this.AuthorizationHeaderParameters != null )
            {
                allParameters.AddRange ( this.AuthorizationHeaderParameters.ToQueryParametersExcludingTokenSecret ( ).Where ( q => q.Key != Parameters.Realm ) );
            }

            allParameters.RemoveAll ( param => param.Key == Parameters.OAuth_Signature );

            ArgumentException.ThrowIfNullOrWhiteSpace ( this.NormalizedRequestUrl );

            string signatureBase = UriUtility.FormatParameters ( this.RequestMethod , new Uri ( this.NormalizedRequestUrl ) , allParameters );

            return signatureBase;
        }

        public Uri GenerateUri ( )
        {
            ArgumentException.ThrowIfNullOrWhiteSpace ( this.NormalizedRequestUrl );

            var builder = new UriBuilder ( this.NormalizedRequestUrl );

            var parameters = this.QueryParameters.ToQueryParametersExcludingTokenSecret ( );

            builder.Query = UriUtility.FormatQueryString ( parameters );

            return builder.Uri;
        }

        public Uri GenerateUriWithoutOAuthParameters ( )
        {
            ArgumentException.ThrowIfNullOrWhiteSpace ( this.NormalizedRequestUrl );

            var builder = new UriBuilder ( this.NormalizedRequestUrl );

            var parameters = this.QueryParameters.ToQueryParameters ( )
                .Where ( q => !q.Key.StartsWith ( Parameters.OAuthParameterPrefix ) && !q.Key.StartsWith ( Parameters.XAuthParameterPrefix ) );

            builder.Query = UriUtility.FormatQueryString ( parameters );

            return builder.Uri;
        }

        public string GenerateUrl ( )
        {
            ArgumentException.ThrowIfNullOrWhiteSpace ( this.NormalizedRequestUrl );

            var builder = new UriBuilder ( this.NormalizedRequestUrl )
            {
                Query = ""
            };

            return builder.Uri + "?" + UriUtility.FormatQueryString ( this.QueryParameters );
        }
    }
}