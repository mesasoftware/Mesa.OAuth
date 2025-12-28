namespace Mesa.OAuth.Consumer.Interfaces
{
    using Mesa.OAuth.Framework.Interfaces;

    public interface IConsumerRequestFactory
    {
        /// <summary>
        /// Creates the consumer request.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="consumerContext">The consumer context.</param>
        /// <param name="token">The token.</param>
        /// <returns></returns>
        IConsumerRequest CreateConsumerRequest ( IOAuthContext context , IOAuthConsumerContext consumerContext , IToken? token );
    }
}