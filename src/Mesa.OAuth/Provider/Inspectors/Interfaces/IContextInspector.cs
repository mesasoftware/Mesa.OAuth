namespace Mesa.OAuth.Provider.Inspectors.Interfaces
{
    using Mesa.OAuth.Framework.Interfaces;

    public interface IContextInspector
    {
        void InspectContext ( ProviderPhase phase , IOAuthContext context );
    }
}