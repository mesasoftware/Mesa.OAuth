namespace Mesa.OAuth.Consumer
{
    using System.Net.Http;
    using Mesa.OAuth.Consumer.Interfaces;
    using Mesa.OAuth.Framework.Interfaces;

    public class ClientCertEnabledConsumerRequest : ConsumerRequest
    {
        private readonly ICertificateFactory certificateFactory;

        /// <summary>
        /// Initializes a new instance of the <see cref="ClientCertEnabledConsumerRequest"/> class.
        /// </summary>
        /// <param name="certificateFactory">The certificate factory.</param>
        /// <param name="context">The context.</param>
        /// <param name="consumerContext">The consumer context.</param>
        /// <param name="token">The token.</param>
        public ClientCertEnabledConsumerRequest (
            ICertificateFactory certificateFactory ,
            IOAuthContext context ,
            IOAuthConsumerContext consumerContext ,
            IToken? token )
            : base ( context , consumerContext , token )
        {
            this.certificateFactory = certificateFactory;
        }

        protected override HttpClientHandler GetHttpClientHandler ( )
        {
            var httpClientHandler = base.GetHttpClientHandler ( );

            var certificate = this.certificateFactory.CreateCertificate ( );

            if ( certificate != null )
            {
                httpClientHandler.ClientCertificates.Add ( certificate );
            }

            return httpClientHandler;
        }
    }
}