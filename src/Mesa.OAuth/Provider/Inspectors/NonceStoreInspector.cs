namespace Mesa.OAuth.Provider.Inspectors
{
    using System;
    using Mesa.OAuth.Framework;
    using Mesa.OAuth.Framework.Interfaces;
    using Mesa.OAuth.Provider.Inspectors.Interfaces;
    using Mesa.OAuth.Storage.Interfaces;

    public class NonceStoreInspector : IContextInspector
    {
        private readonly INonceStore nonceStore;

        public NonceStoreInspector ( INonceStore nonceStore )
        {
            ArgumentNullException.ThrowIfNull ( nonceStore );

            this.nonceStore = nonceStore;
        }

        public void InspectContext ( ProviderPhase phase , IOAuthContext context )
        {
            if ( !this.nonceStore.RecordNonceAndCheckIsUnique ( context , context.Nonce ) )
            {
                throw Error.NonceHasAlreadyBeenUsed ( context );
            }
        }
    }
}