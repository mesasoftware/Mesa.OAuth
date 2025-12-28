namespace Mesa.OAuth.Framework.Signing.Interfaces
{
    using Mesa.OAuth.Framework.Interfaces;

    public interface IOAuthContextSigner
    {
        void SignContext ( IOAuthContext authContext , SigningContext signingContext );

        bool ValidateSignature ( IOAuthContext? authContext , SigningContext? signingContext );
    }
}