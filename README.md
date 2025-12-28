Introduction
------------

The Mesa.OAuth project is a library for creating both OAuth consumers and providers on .NET. It currently targets the .NET 8, 9 and 10, and is written in C#.

Status
-------------
[![.NET](https://github.com/mesasoftware/Mesa.OAuth/actions/workflows/dotnet.yml/badge.svg?branch=main)](https://github.com/mesasoftware/Mesa.OAuth/actions/workflows/dotnet.yml)

What is OAuth
-------------

The definition (from wikipedia) is:

> OAuth is an open protocol that allows users to share their private resources (e.g. photos, videos, contact lists) stored on one site with another site without having to hand out their username and password.

OAuth provides a standardised way to handle delegated Authentication through a series of exchanges, called an authentication flow:

![OAuth authentication flow][1]


What's supported
----------------

The Mesa.OAuth library currently supports building consumers (clients) and providers (servers) for both OAuth 1.0 and 1.0a.

The library is designed to be used in both web applications and thick client apps.

Quick Consumer Example
----------------------

    X509Certificate2 certificate = TestCertificates.OAuthTestCertificate();
    
    string requestUrl = "https://www.google.com/accounts/OAuthGetRequestToken";
    string userAuthorizeUrl = "https://www.google.com/accounts/accounts/OAuthAuthorizeToken";
    string accessUrl = "https://www.google.com/accounts/OAuthGetAccessToken";
    string callBackUrl = "http://www.mysite.com/callback";
    
    var consumerContext = new OAuthConsumerContext
    {
        ConsumerKey = "weitu.googlepages.com",
        SignatureMethod = SignatureMethod.RsaSha1,
        Key = certificate.PrivateKey
    };
    
    var session = new OAuthSession(consumerContext, requestUrl, userAuthorizeUrl, accessUrl)
        .WithQueryParameters(new { scope = "http://www.google.com/m8/feeds" });
    
    // get a request token from the provider
    IToken requestToken = session.GetRequestToken();
    
    // generate a user authorize url for this token (which you can use in a redirect from the current site)
    string authorizationLink = session.GetUserAuthorizationUrlForToken(requestToken, callBackUrl);
    
    // exchange a request token for an access token
    IToken accessToken = session.ExchangeRequestTokenForAccessToken(requestToken);
    
    // make a request for a protected resource
    string responseText = session.Request().Get().ForUrl("http://www.google.com/m8/feeds/contacts/default/base").ToString();


Downloads/Releases
------------------

You can find it on [Nuget][2].

  [1]: https://github.com/mesasoftware/Mesa.OAuth/blob/7a924aaa82faa1ad41c1d5e21a8393104c316d72/artifacts/Oauth_diagram.png
  [2]: https://www.nuget.org/packages/Mesa.OAuth/
