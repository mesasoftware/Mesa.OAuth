namespace Mesa.OAuth.Framework
{
    using System;
    using System.Collections.Specialized;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Text.RegularExpressions;
    using System.Web;
    using Mesa.OAuth.Framework.Interfaces;

    public class OAuthContextBuilder : IOAuthContextBuilder
    {
        private readonly Func<Uri , Uri> emptyUriAdjuster = ( uri ) => uri;

        private readonly Func<Uri , Uri> uriAdjuster;

        public OAuthContextBuilder ( Func<Uri , Uri>? uriAdjuster )
        {
            this.uriAdjuster = uriAdjuster ?? this.emptyUriAdjuster;
        }

        public OAuthContextBuilder ( )
            : this ( null )
        {
        }

        //public virtual IOAuthContext FromHttpRequest(HttpRequest request)
        //{
        //    return FromHttpRequest(new HttpRequestWrapper(request));
        //}

        public virtual IOAuthContext FromHttpRequest ( HttpWebRequest request )
        {
            var context = new OAuthContext
            {
                RawUri = this.CleanUri ( request.RequestUri ) ,
                Cookies = this.CollectCookies ( request ) ,
                Headers = this.GetCleanedNameValueCollection ( request.Headers ) ,
                RequestMethod = request.Method ,

                // TODO: Find out where the hell the form data is.
                //FormEncodedParameters = GetCleanedNameValueCollection(request.Form),
                QueryParameters = this.GetCleanedNameValueCollection ( GetQueryNameValueCollectionFromUri ( request.RequestUri ) ) ,
            };

            if ( request.GetRequestStream ( ).Length > 0 )
            {
                context.RawContent = new byte [ request.GetRequestStream ( ).Length ];
                request.GetRequestStream ( ).Read ( context.RawContent , 0 , context.RawContent.Length );
                request.GetRequestStream ( ).Position = 0;
            }

            this.ParseAuthorizationHeader ( request.Headers , context );

            return context;
        }

        public virtual IOAuthContext FromUri ( string httpMethod , Uri uri )
        {
            uri = this.CleanUri ( uri );

            ArgumentNullException.ThrowIfNull ( httpMethod );

            ArgumentNullException.ThrowIfNull ( uri );

            return new OAuthContext
            {
                RawUri = this.CleanUri ( uri ) ,
                RequestMethod = httpMethod
            };
        }

        public virtual IOAuthContext FromUrl ( string httpMethod , string url )
        {
            return string.IsNullOrEmpty ( url )
                ? throw new ArgumentNullException ( nameof ( url ) )
                : !Uri.TryCreate ( url , UriKind.RelativeOrAbsolute , out var uri )
                ? throw new ArgumentException ( string.Format ( "Failed to parse url: {0} into a valid Uri instance" , url ) )
                : this.FromUri ( httpMethod , uri );
        }

        public virtual IOAuthContext FromWebRequest ( HttpWebRequest request , Stream rawBody )
        {
            using ( var reader = new StreamReader ( rawBody ) )
            {
                return this.FromWebRequest ( request , reader.ReadToEnd ( ) );
            }
        }

        public virtual IOAuthContext FromWebRequest ( HttpWebRequest request , string body )
        {
            var context = new OAuthContext
            {
                RawUri = this.CleanUri ( request.RequestUri ) ,
                Cookies = this.CollectCookies ( request ) ,
                Headers = request.Headers ,
                RequestMethod = request.Method
            };

            string contentType = request.Headers [ HttpRequestHeader.ContentType ] ?? string.Empty;

            if ( contentType.Contains ( "application/x-www-form-urlencoded" , StringComparison.CurrentCultureIgnoreCase ) )
            {
                context.FormEncodedParameters = HttpUtility.ParseQueryString ( body );
            }

            this.ParseAuthorizationHeader ( request.Headers , context );

            return context;
        }

        protected virtual Uri CleanUri ( Uri uri )
        {
            var adjustedUri = this.uriAdjuster ( uri );
            return RemoveEmptyQueryStringParameterIntroducedBySomeOpenSocialPlatformImplementations ( adjustedUri );
        }

        protected virtual NameValueCollection CollectCookies ( WebRequest request )
        {
            return this.CollectCookiesFromHeaderString ( request.Headers [ HttpRequestHeader.Cookie ] );
        }

        protected virtual NameValueCollection CollectCookies ( HttpWebRequest request )
        {
            return this.CollectCookiesFromHeaderString ( request.Headers [ "Set-Cookie" ] );
        }

        protected virtual NameValueCollection CollectCookiesFromHeaderString ( string? cookieHeader )
        {
            NameValueCollection cookieCollection = [ ];

            if ( !string.IsNullOrEmpty ( cookieHeader ) )
            {
                string [ ] cookies = cookieHeader.Split ( ';' );
                foreach ( string cookie in cookies )
                {
                    //Remove the trailing and Leading white spaces
                    string strCookie = cookie.Trim ( );

                    var reg = new Regex ( @"^(\S*)=(\S*)$" , RegexOptions.None , new TimeSpan ( 0 , 0 , 10 ) );

                    if ( reg.IsMatch ( strCookie ) )
                    {
                        var match = reg.Match ( strCookie );
                        if ( match.Groups.Count > 2 )
                        {
                            //HACK: find out why + is coming in as " ".
                            cookieCollection.Add ( match.Groups [ 1 ].Value , HttpUtility.UrlDecode ( match.Groups [ 2 ].Value ).Replace ( ' ' , '+' ) );
                        }
                    }
                }
            }

            return cookieCollection;
        }

        protected virtual NameValueCollection GetCleanedNameValueCollection ( NameValueCollection requestQueryString )
        {
            var nvc = new NameValueCollection ( requestQueryString );

            if ( nvc.HasKeys ( ) )
            {
                nvc.Remove ( null );
            }

            return nvc;
        }

        protected virtual void ParseAuthorizationHeader ( NameValueCollection headers , OAuthContext context )
        {
            if ( headers.AllKeys.Contains ( "Authorization" ) )
            {
                context.AuthorizationHeaderParameters = UriUtility.GetHeaderParameters ( headers [ "Authorization" ] )?.ToNameValueCollection ( );
                context.UseAuthorizationHeader = true;
            }
        }

        private static NameValueCollection GetQueryNameValueCollectionFromUri ( Uri uri )
        {
            NameValueCollection result = [ ];

            if ( !string.IsNullOrWhiteSpace ( uri.Query ) )
            {
                foreach ( string paramNameAndValue in uri.Query.Split ( '&' ) )
                {
                    string [ ] parts = paramNameAndValue.Split ( '=' );

                    result.Add ( parts.First ( ) , parts.Last ( ) );
                }
            }

            return result;
        }

        private static Uri RemoveEmptyQueryStringParameterIntroducedBySomeOpenSocialPlatformImplementations ( Uri adjustedUri )
        {
            // this is a fix for OpenSocial platforms sometimes appending an empty query string parameter
            // to their url.

            string originalUrl = adjustedUri.OriginalString;
            return originalUrl.EndsWith ( '&' ) ? new Uri ( originalUrl [ ..^1 ] ) : adjustedUri;
        }
    }
}