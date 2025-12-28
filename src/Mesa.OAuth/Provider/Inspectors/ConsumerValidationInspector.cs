namespace Mesa.OAuth.Provider.Inspectors
{
    using System;
    using Mesa.OAuth.Framework;
    using Mesa.OAuth.Framework.Interfaces;
    using Mesa.OAuth.Provider.Inspectors.Interfaces;
    using Mesa.OAuth.Storage.Interfaces;

    public class ConsumerValidationInspector : IContextInspector
    {
        private readonly IConsumerStore consumerStore;

        public ConsumerValidationInspector ( IConsumerStore consumerStore )
        {
            ArgumentNullException.ThrowIfNull ( consumerStore );

            this.consumerStore = consumerStore;
        }

        public void InspectContext ( ProviderPhase phase , IOAuthContext context )
        {
            if ( !this.consumerStore.IsConsumer ( context ) )
            {
                throw Error.UnknownConsumerKey ( context );
            }
        }
    }
}