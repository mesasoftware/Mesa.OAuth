namespace Mesa.OAuth.Consumer
{
    using System;
    using System.Net;
    using Mesa.OAuth.Framework;
    using Mesa.OAuth.Framework.Interfaces;
    using Mesa.OAuth.Utility;

    public static class WebExceptionHelper
    {
        /// <summary>
        /// Will attempt to wrap the exception, returning true if the exception was wrapped, or returning false if it was not (in which case
        /// the original exception should be thrown).
        /// </summary>
        /// <param name="requestContext"></param>
        /// <param name="webEx"></param>
        /// <param name="authException"></param>
        /// <returns><c>true</c>, if the authException should be throw, <c>false</c> if the original web exception should be thrown</returns>
        public static bool TryWrapException (
            IOAuthContext requestContext ,
            WebException webEx ,
            out OAuthException authException ,
            Action<string>? responseBodyAction )
        {
            string content = webEx.Response?.ReadToEnd ( ) ?? string.Empty;

            responseBodyAction?.Invoke ( content );

            if ( content.Contains ( Parameters.OAuth_Problem ) )
            {
                var report = new OAuthProblemReport ( content );

                authException = new OAuthException ( report.ProblemAdvice ?? report.Problem ?? string.Empty , webEx )
                {
                    Context = requestContext ,
                    Report = report
                };

                return true;
            }

            authException = new OAuthException ( );

            return false;
        }
    }
}