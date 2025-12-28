namespace Mesa.OAuth.Tests
{
    using System;
    using System.Text;
    using Mesa.OAuth.Consumer;
    using Mesa.OAuth.Framework;
    using Mesa.OAuth.Storage.Basic;

    public class ConsumerTests
    {
        public class ConsumerRequestTests
        {
            [Fact]
            public void GetRequestDescription_GivenHeader_ShouldReturnDescriptionWithHeader ( )
            {
                // Arrange.
                var context = new OAuthContext
                {
                    RequestMethod = "POST" ,
                    RawUri = new Uri ( "http://localhost/svc" )
                };

                var consumerContext = new OAuthConsumerContext
                {
                    ConsumerKey = "key" ,
                    ConsumerSecret = "secret" ,
                    SignatureMethod = SignatureMethod.PlainText
                };

                var accessToken = new AccessToken ( );

                string key = "a-key";
                string expected = "a-value";

                context.Headers [ key ] = expected;

                var request = new ConsumerRequest ( context , consumerContext , accessToken );

                // Act.
                var description = request.GetRequestDescription ( );
                string? actual = description.Headers [ key ];

                // Assert.
                Assert.NotNull ( actual );
                Assert.Equal ( expected , actual );
            }
        }

        public class OAuthSessionTests
        {
            public class CreateSessionTests
            {
                [Fact]
                public void CreateSession_GivenContextOnly_DoesNotThrowException ( )
                {
                    // Arrange.
                    var context = new OAuthConsumerContext ( );

                    // Act.
                    OAuthSession? session = null;

                    var exception = Record.Exception ( ( ) => session = new OAuthSession ( context ) );

                    // Assert.
                    Assert.Null ( exception );
                    Assert.NotNull ( session );
                }
            }

            public class GetRequestDescriptionTests
            {
                [Fact]
                public void GetRequestDescription_GivenCallbackUrl_ShouldReturnDescriptionWithCallbackUrl ( )
                {
                    // Arrange.
                    var consumerContext = new OAuthConsumerContext
                    {
                        ConsumerKey = "key"
                    };

                    var session = new OAuthSession (
                        consumerContext ,
                        "http://localhost/request" ,
                        "http://localhost/userauth" ,
                        "http://localhost/access" ,
                        "http://localhost/callback" );

                    string expected = "oauth_callback=http%3A%2F%2Flocalhost%2Fcallback";

                    // Act.
                    var actual = session.BuildRequestTokenContext ( "POST" )
                        .GetRequestDescription ( );

                    // Assert.
                    Assert.NotNull ( actual );
                    Assert.Contains ( expected , actual.Body );
                }

                [Fact]
                public void GetRequestDescription_GivenPlaceholderCallbackUrl_ShouldReturnDescriptionWithPlaceholderCallbackUrl ( )
                {
                    // Arrange.
                    var consumerContext = new OAuthConsumerContext { ConsumerKey = "key" };

                    var session = new OAuthSession (
                        consumerContext ,
                        "http://localhost/request" ,
                        "http://localhost/userauth" ,
                        "http://localhost/access" );

                    string expected = "oauth_callback=oob";

                    // Act.
                    var actual = session.BuildRequestTokenContext ( "POST" )
                        .GetRequestDescription ( );

                    // Assert.
                    Assert.NotNull ( actual );
                    Assert.Contains ( expected , actual.Body );
                }

                [Fact]
                public void GetRequestDescription_GivenRequestWithBody_ShouldReturnDescriptionWithBodyHash ( )
                {
                    // Arrange.
                    var session = new OAuthSession (
                        new OAuthConsumerContext
                        {
                            ConsumerKey = "consumer" ,
                            UseHeaderForOAuthParameters = true
                        } ,
                        "http://localhost/request" ,
                        "http://localhost/userauth" ,
                        "http://localhost/access" );

                    var accessToken = new TokenBase
                    {
                        ConsumerKey = "consumer" ,
                        Token = "token" ,
                        TokenSecret = "secret"
                    };

                    byte [ ] expectedBody = Encoding.UTF8.GetBytes ( "Hello World!" );
                    string expectedHeader = "oauth_body_hash=\"Lve95gjOVATpfV8EL5X4nxwjKHE%3D\"";

                    var content = session.EnableOAuthRequestBodyHashes ( )
                        .Request ( accessToken )
                        .Post ( )
                        .ForUrl ( "http://localhost/resource" )
                        .WithRawContent ( expectedBody );

                    // Act.
                    var actual = content.GetRequestDescription ( );

                    // Assert.
                    Assert.NotNull ( actual.Headers );
                    Assert.NotNull ( actual.RawBody );
                    Assert.Equal ( expectedBody , actual.RawBody );
                    Assert.Contains ( expectedHeader , actual.Headers [ Parameters.OAuth_Authorization_Header ] );
                }

                [Fact]
                public void GetRequestDescription_WhenUseHeaderForOAuthParametersIsFalse_ShouldNotIncludeTokenSecretInBody ( )
                {
                    // Arrange.
                    var session = new OAuthSession (
                        new OAuthConsumerContext
                        {
                            ConsumerKey = "consumer"
                        } ,
                        "http://localhost/request" ,
                        "http://localhost/userauth" ,
                        "http://localhost/access" );

                    var accessToken = new TokenBase
                    {
                        ConsumerKey = "consumer" ,
                        Token = "token" ,
                        TokenSecret = "secret"
                    };

                    // Act.
                    var actual = session
                        .Request ( accessToken )
                        .Post ( )
                        .ForUrl ( "http://localhost/" )
                        .SignWithToken ( )
                        .GetRequestDescription ( );

                    // Assert.
                    Assert.NotNull ( actual );
                    Assert.DoesNotContain ( Parameters.OAuth_Token_Secret , actual.Body );
                }

                [Fact]
                public void GetRequestDescription_WhenUseHeaderForOAuthParametersIsFalse_ShouldNotIncludeTokenSecretInUrlQuery ( )
                {
                    // Arrange.
                    var session = new OAuthSession (
                        new OAuthConsumerContext
                        {
                            ConsumerKey = "consumer"
                        } ,
                        "http://localhost/request" ,
                        "http://localhost/userauth" ,
                        "http://localhost/access" );

                    var accessToken = new TokenBase
                    {
                        ConsumerKey = "consumer" ,
                        Token = "token" ,
                        TokenSecret = "secret"
                    };

                    // Act.
                    var actual = session.Request ( accessToken )
                        .Get ( )
                        .ForUrl ( "http://localhost/" )
                        .SignWithToken ( )
                        .GetRequestDescription ( );

                    // Assert.
                    Assert.NotNull ( actual );
                    Assert.DoesNotContain ( Parameters.OAuth_Token_Secret , actual.Url?.ToString ( ) );
                }

                [Fact]
                public void GetRequestDescription_WhenUseHeaderForOAuthParametersIsTrue_ShouldNotIncludeTokenSecretInAuthorizationHeader ( )
                {
                    // Arrange.
                    var session = new OAuthSession (
                        new OAuthConsumerContext
                        {
                            ConsumerKey = "consumer" ,
                            UseHeaderForOAuthParameters = true
                        } ,
                        "http://localhost/request" ,
                        "http://localhost/userauth" ,
                        "http://localhost/access" );

                    var accessToken = new TokenBase
                    {
                        ConsumerKey = "consumer" ,
                        Token = "token" ,
                        TokenSecret = "secret"
                    };

                    // Act.
                    var actual = session.Request ( accessToken )
                        .Post ( )
                        .ForUrl ( "http://localhost/" )
                        .SignWithToken ( )
                        .GetRequestDescription ( );

                    // Assert.
                    Assert.NotNull ( actual );
                    Assert.DoesNotContain ( Parameters.OAuth_Token_Secret , actual.Headers [ "Authorization" ] );
                }
            }

            public class GetRequestTokenTests
            {
                [Fact]
                public void GetRequestToken_WithGetHttpMethod_ShouldNotPopulateBody ( )
                {
                    // Arrange.
                    var consumerContext = new OAuthConsumerContext { ConsumerKey = "key" };

                    var session = new OAuthSession (
                        consumerContext ,
                        "http://localhost/request" ,
                        "http://localhost/userauth" ,
                        "http://localhost/access" );

                    string expected = "GET";

                    // Act.
                    var actual = session.BuildRequestTokenContext ( "GET" )
                        .GetRequestDescription ( );

                    // Assert.
                    Assert.NotNull ( actual );
                    Assert.Null ( actual.Body );
                    Assert.Null ( actual.ContentType );
                    Assert.Equal ( expected , actual.Method );
                }
            }

            public class GetUserAuthorizationUrlForTokenTests
            {
                [Fact]
                public void GetUserAuthorizationUrlForToken_GivenCallbackUrl_ShouldBeEqual ( )
                {
                    // Arrange.
                    var session = new OAuthSession (
                        new OAuthConsumerContext ( ) ,
                        "http://localhost/request" ,
                        "http://localhost/userauth" ,
                        "http://localhost/access" );

                    string expected = "http://localhost/userauth?oauth_token=token&oauth_callback=http%3A%2F%2Flocalhost%2Fcallback";

                    // Act.
                    string actual = session.GetUserAuthorizationUrlForToken (
                        new TokenBase
                        {
                            Token = "token"
                        } ,
                        "http://localhost/callback" );

                    // Assert.
                    Assert.Equal ( expected , actual );
                }

                [Fact]
                public void GetUserAuthorizationUrlForToken_GivenNoCallbackUrl_ShouldBeEqual ( )
                {
                    // Arrange.
                    var session = new OAuthSession (
                        new OAuthConsumerContext ( ) ,
                        "http://localhost/request" ,
                        "http://localhost/userauth" ,
                        "http://localhost/access" );

                    string expected = "http://localhost/userauth?oauth_token=token";

                    // Act.
                    string actual = session.GetUserAuthorizationUrlForToken (
                        new TokenBase
                        {
                            Token = "token"
                        } ,
                        null );

                    // Assert.
                    Assert.Equal ( expected , actual );
                }
            }
        }
    }
}