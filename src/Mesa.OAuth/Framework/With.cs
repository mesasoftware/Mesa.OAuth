namespace Mesa.OAuth.Framework
{
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;

    public static class With
    {
        public static IDisposable NoCertificateValidation ( )
        {
            var oldCallback = ServicePointManager.ServerCertificateValidationCallback;

            ServicePointManager.ServerCertificateValidationCallback = CertificateAlwaysValidCallback;

            return new DisposableAction (
                delegate
                {
                    ServicePointManager.ServerCertificateValidationCallback = oldCallback;
                } );
        }

        private static bool CertificateAlwaysValidCallback (
            object sender ,
            X509Certificate? certificate ,
            X509Chain? chain ,
            SslPolicyErrors sslPolicyErrors )
        {
            return true;
        }
    }

    public class DisposableAction : IDisposable
    {
        private readonly Action action;

        public DisposableAction ( Action action )
        {
            ArgumentNullException.ThrowIfNull ( action );

            this.action = action;
        }

        public void Dispose ( )
        {
            this.action ( );

            GC.SuppressFinalize ( this );
        }
    }
}