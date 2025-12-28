namespace Mesa.OAuth.Consumer.Interfaces
{
    using System;
    using System.Collections.Specialized;
    using System.Net.Http;
    using System.Threading.Tasks;
    using System.Xml.Linq;
    using Mesa.OAuth.Consumer;
    using Mesa.OAuth.Framework.Interfaces;

    public interface IConsumerRequest
    {
        string? AcceptsType { get; set; }

        IOAuthConsumerContext ConsumerContext { get; }

        IOAuthContext Context { get; }

        Uri? ProxyServerUri { get; set; }

        string? RequestBody { get; set; }

        Action<string>? ResponseBodyAction { get; set; }

        int? Timeout { get; set; }

        RequestDescription GetRequestDescription ( );

        IConsumerRequest SignWithoutToken ( );

        IConsumerRequest SignWithToken ( );

        IConsumerRequest SignWithToken ( IToken token );

        Task<NameValueCollection> ToBodyParametersAsync ( );

        Task<byte [ ]> ToBytesAsync ( );

        HttpRequestMessage ToRequestMessage ( );

        Task<HttpResponseMessage> ToResponseMessageAsync ( );

        Task<string> ToStringAsync ( );

        Task<XDocument> ToXDocumentAsync ( );
    }
}