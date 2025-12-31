namespace Mesa.OAuth.Framework.Signing
{
    using System;
    using System.Collections.Generic;
    using Mesa.OAuth.Framework.Interfaces;
    using Mesa.OAuth.Framework.Signing.Interfaces;

    public class OAuthContextSigner : IOAuthContextSigner
    {
        private readonly List<IContextSignatureImplementation> implementations = [ ];

        public OAuthContextSigner ( params IContextSignatureImplementation [ ] implementations )
        {
            if ( implementations != null )
            {
                this.implementations.AddRange ( implementations );
            }
        }

        public OAuthContextSigner ( ) : this (
                new RsaSha1SignatureImplementation ( ) ,
                new HmacSha1SignatureImplementation ( ) ,
                new PlainTextSignatureImplementation ( ) )
        {
        }

        public void SignContext ( IOAuthContext authContext , SigningContext signingContext )
        {
            signingContext.SignatureBase = authContext.GenerateSignatureBase ( );
            this.FindImplementationForAuthContext ( authContext ).SignContext ( authContext , signingContext );
        }

        public bool ValidateSignature ( IOAuthContext? authContext , SigningContext? signingContext )
        {
#if NET10_0_OR_GREATER
            signingContext?.SignatureBase = authContext?.GenerateSignatureBase ( );
#else
            if ( signingContext is not null )
            {
                signingContext.SignatureBase = authContext?.GenerateSignatureBase ( );
            }
#endif

            return this.FindImplementationForAuthContext ( authContext ).ValidateSignature ( authContext , signingContext );
        }

        private IContextSignatureImplementation FindImplementationForAuthContext ( IOAuthContext? authContext )
        {
            ArgumentNullException.ThrowIfNull ( authContext );

            var impl = this.implementations.Find ( i => i.MethodName == authContext.SignatureMethod );

            return impl ?? throw Error.UnknownSignatureMethod ( authContext.SignatureMethod ?? string.Empty );
        }
    }
}