namespace Mesa.OAuth.Framework.Interfaces
{
    using System;
    using System.IO;
    using System.Net;

    public interface IOAuthContextBuilder
    {
        IOAuthContext FromUri ( string httpMethod , Uri uri );

        IOAuthContext FromUrl ( string httpMethod , string url );

        IOAuthContext FromWebRequest ( HttpWebRequest request , Stream rawBody );

        IOAuthContext FromWebRequest ( HttpWebRequest request , string body );
    }
}