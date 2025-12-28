namespace Mesa.OAuth.Consumer
{
    using System;
    using System.Collections.Specialized;

    public class RequestDescription
    {
        public RequestDescription ( )
        {
            this.Headers = [ ];
        }

        public string? Body { get; set; }

        public string? ContentType { get; set; }

        public NameValueCollection Headers { get; private set; }

        public string? Method { get; set; }

        public byte [ ]? RawBody { get; set; }

        public Uri? Url { get; set; }
    }
}