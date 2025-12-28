namespace Mesa.OAuth.Provider.Inspectors
{
    using Mesa.OAuth.Framework;
    using Mesa.OAuth.Framework.Interfaces;
    using Mesa.OAuth.Provider.Inspectors.Interfaces;
    using Mesa.OAuth.Utility;

    public class BodyHashValidationInspector : IContextInspector
    {
        public void InspectContext ( ProviderPhase phase , IOAuthContext context )
        {
            if ( context.SignatureMethod == SignatureMethod.PlainText ||
                string.IsNullOrEmpty ( context.BodyHash ) )
            {
                return;
            }

            if ( !string.IsNullOrEmpty ( context.BodyHash )
                && context.FormEncodedParameters.Count > 0 )
            {
                throw Error.EncounteredUnexpectedBodyHashInFormEncodedRequest ( context );
            }

            if ( !context.BodyHash.EqualsInConstantTime ( context.GenerateBodyHash ( ) ) )
            {
                throw Error.FailedToValidateBodyHash ( context );
            }
        }
    }
}