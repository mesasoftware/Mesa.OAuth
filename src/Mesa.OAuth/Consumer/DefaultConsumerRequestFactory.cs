namespace Mesa.OAuth.Consumer
{
    using System;
    using Mesa.OAuth.Consumer.Interfaces;
    using Mesa.OAuth.Framework.Interfaces;

    public class DefaultConsumerRequestFactory : IConsumerRequestFactory
    {
        public static readonly DefaultConsumerRequestFactory Instance = new DefaultConsumerRequestFactory ( );

        public IConsumerRequest CreateConsumerRequest ( IOAuthContext context , IOAuthConsumerContext consumerContext , IToken? token )
        {
            ArgumentNullException.ThrowIfNull ( context );

            ArgumentNullException.ThrowIfNull ( consumerContext );

            return new ConsumerRequest ( context , consumerContext , token );
        }
    }
}