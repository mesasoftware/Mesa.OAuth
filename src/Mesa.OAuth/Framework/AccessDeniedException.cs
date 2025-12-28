namespace Mesa.OAuth.Framework
{
    using System;
    using Mesa.OAuth.Provider;

    public class AccessDeniedException : Exception
    {
        public AccessDeniedException ( AccessOutcome outcome , string? message ) : base ( message )
        {
            this.Outcome = outcome;
        }

        public AccessOutcome Outcome { get; }
    }
}