namespace Mesa.OAuth.Framework
{
    using System;
    using Mesa.OAuth.Framework.Interfaces;

    /// <summary>
    /// Generates unique nonces (via Guids) to let the server detect duplicated requests.
    /// </summary>
    public class GuidNonceGenerator : INonceGenerator
    {
        protected Random random = new Random ( );

        public string GenerateNonce ( IOAuthContext context )
        {
            return Guid.NewGuid ( ).ToString ( );
        }
    }
}