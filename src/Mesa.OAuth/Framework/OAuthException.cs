namespace Mesa.OAuth.Framework
{
    using System;
    using Mesa.OAuth.Framework.Interfaces;

    public class OAuthException : Exception
    {
        public OAuthException ( )
        {
        }

        public OAuthException ( string message , Exception innerException )
            : base ( message , innerException )
        {
        }

        public OAuthException ( IOAuthContext context , string problem , string advice ) : base ( advice )
        {
            this.Context = context;
            this.Report = new OAuthProblemReport { Problem = problem , ProblemAdvice = advice };
        }

        public OAuthException ( IOAuthContext context , string problem , string advice , Exception innerException )
            : base ( advice , innerException )
        {
            this.Context = context;
            this.Report = new OAuthProblemReport { Problem = problem , ProblemAdvice = advice };
        }

        public IOAuthContext? Context { get; set; }

        public OAuthProblemReport? Report { get; set; }
    }
}