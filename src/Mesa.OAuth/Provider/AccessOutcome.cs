namespace Mesa.OAuth.Provider
{
    using Mesa.OAuth.Framework.Interfaces;

    public class AccessOutcome
    {
        public string? AdditionalInfo { get; set; }

        public IOAuthContext? Context { get; set; }

        public bool Granted { get; set; }
    }
}