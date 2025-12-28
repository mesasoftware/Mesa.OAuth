namespace Mesa.OAuth.Provider.Inspectors
{
    using System;
    using Mesa.OAuth.Framework;
    using Mesa.OAuth.Framework.Interfaces;
    using Mesa.OAuth.Provider.Inspectors.Interfaces;

    public class XAuthValidationInspector : IContextInspector
    {
        private readonly Func<string , string , bool> authenticateFunc;

        private readonly Func<string , bool> validateModeFunc;

        public XAuthValidationInspector ( Func<string , bool> validateModeFunc , Func<string , string , bool> authenticateFunc )
        {
            this.validateModeFunc = validateModeFunc;
            this.authenticateFunc = authenticateFunc;
        }

        public void InspectContext ( ProviderPhase phase , IOAuthContext context )
        {
            if ( phase != ProviderPhase.CreateAccessToken )
            {
                return;
            }

            string? authMode = context.XAuthMode;

            if ( string.IsNullOrEmpty ( authMode ) )
            {
                throw Error.EmptyXAuthMode ( context );
            }

            if ( !this.validateModeFunc ( authMode ) )
            {
                throw Error.InvalidXAuthMode ( context );
            }

            string? username = context.XAuthUsername;

            if ( string.IsNullOrEmpty ( username ) )
            {
                throw Error.EmptyXAuthUsername ( context );
            }

            string? password = context.XAuthPassword;

            if ( string.IsNullOrEmpty ( password ) )
            {
                throw Error.EmptyXAuthPassword ( context );
            }

            if ( !this.authenticateFunc ( username , password ) )
            {
                throw Error.FailedXAuthAuthentication ( context );
            }
        }
    }
}