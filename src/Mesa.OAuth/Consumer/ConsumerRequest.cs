namespace Mesa.OAuth.Consumer
{
    using System;
    using System.Collections.Specialized;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;
    using System.Web;
    using System.Xml.Linq;
    using Mesa.OAuth.Consumer.Interfaces;
    using Mesa.OAuth.Framework;
    using Mesa.OAuth.Framework.Interfaces;
    using Mesa.OAuth.Utility;

    public class ConsumerRequest : IConsumerRequest
    {
        private readonly IToken? token;

        private HttpClient? httpClient;

        public ConsumerRequest ( IOAuthContext context , IOAuthConsumerContext consumerContext , IToken? token )
        {
            ArgumentNullException.ThrowIfNull ( context );

            ArgumentNullException.ThrowIfNull ( consumerContext );

            this.Context = context;
            this.ConsumerContext = consumerContext;
            this.token = token;
        }

        public string? AcceptsType { get; set; }

        public IOAuthConsumerContext ConsumerContext { get; }

        public IOAuthContext Context { get; }

        public Uri? ProxyServerUri { get; set; }

        public string? RequestBody { get; set; }

        public Action<string>? ResponseBodyAction { get; set; }

        /// <summary>
        /// Override the default request timeout in milliseconds.
        /// Sets the <see cref="HttpWebRequest.Timeout"/> property.
        /// </summary>
        public int? Timeout { get; set; }

        private string? ResponseBody { get; set; }

        public RequestDescription GetRequestDescription ( )
        {
            if ( string.IsNullOrEmpty ( this.Context.Signature ) )
            {
                if ( this.token != null )
                {
                    this.ConsumerContext.SignContextWithToken ( this.Context , this.token );
                }
                else
                {
                    this.ConsumerContext.SignContext ( this.Context );
                }
            }

            var uri = this.Context.GenerateUri ( );

            var description = new RequestDescription
            {
                Url = uri ,
                Method = this.Context.RequestMethod ,
            };

            if ( ( this.Context.FormEncodedParameters != null ) && ( this.Context.FormEncodedParameters.Count > 0 ) )
            {
                description.ContentType = Parameters.HttpFormEncoded;
                description.Body = UriUtility.FormatQueryString ( this.Context.FormEncodedParameters.ToQueryParametersExcludingTokenSecret ( ) );
            }
            else if ( !string.IsNullOrEmpty ( this.RequestBody ) )
            {
                description.Body = UriUtility.UrlEncode ( this.RequestBody );
            }
            else if ( this.Context.RawContent != null )
            {
                description.ContentType = this.Context.RawContentType;
                description.RawBody = this.Context.RawContent;
            }

            if ( this.Context.Headers != null )
            {
                description.Headers.Add ( this.Context.Headers );
            }

            if ( this.ConsumerContext.UseHeaderForOAuthParameters )
            {
                description.Headers [ Parameters.OAuth_Authorization_Header ] = this.Context.GenerateOAuthParametersForHeader ( );
            }

            return description;
        }

        public IConsumerRequest SignWithoutToken ( )
        {
            this.EnsureRequestHasNotBeenSignedYet ( );
            this.ConsumerContext.SignContext ( this.Context );
            return this;
        }

        public IConsumerRequest SignWithToken ( )
        {
            return this.SignWithToken ( this.token );
        }

        public IConsumerRequest SignWithToken ( IToken? token )
        {
            ArgumentNullException.ThrowIfNull ( token );

            this.EnsureRequestHasNotBeenSignedYet ( );
            this.ConsumerContext.SignContextWithToken ( this.Context , token );
            return this;
        }

        public async Task<NameValueCollection> ToBodyParametersAsync ( )
        {
            try
            {
                string encodedFormParameters = await this.ToStringAsync ( );

                this.ResponseBodyAction?.Invoke ( encodedFormParameters );

                try
                {
                    return HttpUtility.ParseQueryString ( encodedFormParameters );
                }
                catch ( ArgumentNullException )
                {
                    throw Error.FailedToParseResponse ( encodedFormParameters );
                }
            }
            catch ( WebException webEx )
            {
                throw Error.RequestFailed ( webEx );
            }
        }

        public async Task<byte [ ]> ToBytesAsync ( )
        {
            return Convert.FromBase64String ( await this.ToStringAsync ( ) );
        }

        public HttpRequestMessage ToRequestMessage ( )
        {
            var description = this.GetRequestDescription ( );

            ArgumentNullException.ThrowIfNull ( description.Url );
            ArgumentException.ThrowIfNullOrWhiteSpace ( description.Method );

            var requestMessage = new HttpRequestMessage (
                description.Method.ToHttpMethod ( ) ,
                description.Url );

            if ( !string.IsNullOrEmpty ( this.AcceptsType ) )
            {
                requestMessage.Headers.Accept.Add (
                    MediaTypeWithQualityHeaderValue.Parse (
                        this.AcceptsType ) );
            }

            try
            {
                string? modifiedDateString = this.Context.Headers [ "If-Modified-Since" ];

                if ( modifiedDateString != null )
                {
                    requestMessage.Headers.IfModifiedSince = DateTime.Parse ( modifiedDateString );
                }
            }
            catch ( Exception ex )
            {
                throw new ApplicationException ( "If-Modified-Since header could not be parsed as a datetime" , ex );
            }

            if ( description.Headers.Count > 0 )
            {
                foreach ( string key in description.Headers )
                {
                    requestMessage.Headers.Add ( key , description.Headers [ key ] );
                }
            }

            if ( !string.IsNullOrEmpty ( description.Body ) )
            {
                requestMessage.Content = new StringContent ( description.Body );
            }
            else if ( description.RawBody != null && description.RawBody.Length > 0 )
            {
                requestMessage.Content = new ByteArrayContent ( description.RawBody );
            }

            return requestMessage;
        }

        public async Task<HttpResponseMessage> ToResponseMessageAsync ( )
        {
            try
            {
                var requestMessage = this.ToRequestMessage ( );

                using ( var httpClient = this.GetHttpClient ( ) )
                {
                    return await httpClient.SendAsync ( requestMessage );
                }
            }
            catch ( WebException webEx )
            {
                if ( WebExceptionHelper.TryWrapException ( this.Context , webEx , out var authException , this.ResponseBodyAction ) )
                {
                    throw authException;
                }

                throw;
            }
        }

        public async Task<string> ToStringAsync ( )
        {
            if ( string.IsNullOrEmpty ( this.ResponseBody ) )
            {
                var responseMessage = await this.ToResponseMessageAsync ( );

                this.ResponseBody = await responseMessage.Content
                    .ReadAsStringAsync ( );
            }

            return this.ResponseBody;
        }

        public async Task<XDocument> ToXDocumentAsync ( )
        {
            return XDocument.Parse ( await this.ToStringAsync ( ) );
        }

        protected virtual HttpClientHandler GetHttpClientHandler ( )
        {
            var httpClientHandler = new HttpClientHandler ( );

            if ( this.ProxyServerUri != null )
            {
                httpClientHandler.Proxy = new WebProxy ( this.ProxyServerUri , false );
            }

            return httpClientHandler;
        }

        private void EnsureRequestHasNotBeenSignedYet ( )
        {
            if ( !string.IsNullOrEmpty ( this.Context.Signature ) )
            {
                throw Error.ThisConsumerRequestHasAlreadyBeenSigned ( );
            }
        }

        private HttpClient GetHttpClient ( )
        {
            this.httpClient ??= new HttpClient (
                    this.GetHttpClientHandler ( ) );

            return this.httpClient;
        }
    }
}