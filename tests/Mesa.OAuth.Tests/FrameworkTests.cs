namespace Mesa.OAuth.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using Mesa.OAuth.Framework;

    public class FrameworkTests
    {
        public class DateTimeUtilityTests
        {
            [Fact]
            public void FromEpoch_GivenNewYearsDate_ShouldBeEqual ( )
            {
                // Arrange.
                var expected = new DateTime ( 2008 , 1 , 1 , 0 , 0 , 0 );

                long epoch = expected.Epoch ( );

                // Act.
                var actual = DateTimeUtility.FromEpoch ( ( int ) epoch );

                // Assert.
                Assert.Equal ( expected , actual );
            }
        }

        public class OAuthContextTests
        {
            public class GenerateBodyHash
            {
                [Fact]
                public void GenerateBodyHash_GivenEmptyContext_ShouldBeEqual ( )
                {
                    // Arrange & Act.
                    var context = new OAuthContext ( );

                    string expected = "2jmj7l5rSw0yVb/vlWAYkK/YBwk=";

                    // Act.
                    string actual = context.GenerateBodyHash ( );

                    // Assert.
                    Assert.Equal ( expected , actual );
                }
            }

            public class GenerateSignatureBase
            {
                [Fact]
                public void GenerateSignatureBase_GivenBodyWithHelloWorld_ShouldBeEqual ( )
                {
                    // Arrange.
                    var context = new OAuthContext
                    {
                        RequestMethod = "POST" ,
                        RawUri = new Uri ( "http://www.example.com/resource" ) ,
                        RawContentType = "text/plain" ,
                        RawContent = Encoding.UTF8.GetBytes ( "Hello World!" ) ,
                        ConsumerKey = "consumer" ,
                        SignatureMethod = "HMAC-SHA1" ,
                        Timestamp = "1236874236" ,
                        Version = "1.0" ,
                        IncludeOAuthRequestBodyHashInSignature = true ,
                        Nonce = "10369470270925" ,
                        Token = "token"
                    };

                    string expected = "POST&http%3A%2F%2Fwww.example.com%2Fresource&oauth_body_hash%3DLve95gjOVATpfV8EL5X4nxwjKHE%253D%26oauth_consumer_key%3Dconsumer%26oauth_nonce%3D10369470270925%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1236874236%26oauth_token%3Dtoken%26oauth_version%3D1.0";

                    // Act.
                    string actual = context.GenerateSignatureBase ( );

                    // Assert.
                    Assert.Equal ( expected , actual );
                }

                [Fact]
                public void GenerateSignatureBase_GivenXAuthParameters_ShouldBeEqual ( )
                {
                    // Arrange.
                    var context = new OAuthContext
                    {
                        RawUri = new Uri ( "https://api.twitter.com/oauth/access_token" ) ,
                        RequestMethod = "POST" ,
                        ConsumerKey = "JvyS7DO2qd6NNTsXJ4E7zA" ,
                        SignatureMethod = "HMAC-SHA1" ,
                        Timestamp = "1284565601" ,
                        Version = "1.0" ,
                        Nonce = "6AN2dKRzxyGhmIXUKSmp1JcB4pckM8rD3frKMTmVAo" ,
                        XAuthMode = "client_auth" ,
                        XAuthUsername = "oauth_test_exec" ,
                        XAuthPassword = "twitter-xauth"
                    };

                    string expected = "POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Faccess_token&oauth_consumer_key%3DJvyS7DO2qd6NNTsXJ4E7zA%26oauth_nonce%3D6AN2dKRzxyGhmIXUKSmp1JcB4pckM8rD3frKMTmVAo%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1284565601%26oauth_version%3D1.0%26x_auth_mode%3Dclient_auth%26x_auth_password%3Dtwitter-xauth%26x_auth_username%3Doauth_test_exec";

                    // Act.
                    string actual = context.GenerateSignatureBase ( );

                    // Assert.
                    Assert.Equal ( expected , actual );
                }

                [Fact]
                public void GenerateSignatureBase_WhenTokenIsUrlEncoded_ShouldBeEqual ( )
                {
                    // Arrange.
                    var context = new OAuthContext
                    {
                        RequestMethod = "GET" ,
                        RawUri = new Uri ( "https://www.google.com/m8/feeds/contacts/default/base" ) ,
                        Token = "1/2" ,
                        ConsumerKey = "context" ,
                        SignatureMethod = SignatureMethod.RsaSha1
                    };

                    string expected = "GET&https%3A%2F%2Fwww.google.com%2Fm8%2Ffeeds%2Fcontacts%2Fdefault%2Fbase&oauth_consumer_key%3Dcontext%26oauth_signature_method%3DRSA-SHA1%26oauth_token%3D1%252F2";

                    // Act.
                    string actual = context.GenerateSignatureBase ( );

                    // Assert.
                    Assert.Equal ( expected , actual );
                }
            }

            public class GenerateUrl
            {
                [Fact]
                public void GenerateUrl_WhenTokenIsUrlEncoded_ShouldBeEqual ( )
                {
                    // Arrange.
                    var context = new OAuthContext
                    {
                        RequestMethod = "GET" ,
                        RawUri = new Uri ( "https://www.google.com/m8/feeds/contacts/default/base" ) ,
                        Token = "1/2" ,
                        ConsumerKey = "context" ,
                        SignatureMethod = SignatureMethod.RsaSha1
                    };

                    string expected = "https://www.google.com/m8/feeds/contacts/default/base?oauth_token=1%2F2&oauth_consumer_key=context&oauth_signature_method=RSA-SHA1";

                    // Act.
                    string actual = context.GenerateUrl ( );

                    // Assert.
                    Assert.Equal ( expected , actual );
                }
            }
        }

        public class OAuthProblemReportTests
        {
            [Fact]
            public void ToString_GivenFormattedConsumerKeyRefusedProblemWithAdvice_ShouldBeEqual ( )
            {
                // Arrange.
                string formatted = "oauth_problem=consumer_key_refused&oauth_problem_advice=The%20supplied%20consumer%20key%20has%20been%20black-listed%20due%20to%20complaints.";

                // Act.
                var report = new OAuthProblemReport ( formatted );

                // Assert.
                Assert.NotNull ( report.Problem );
                Assert.Equal ( OAuthProblems.ConsumerKeyRefused , report.Problem );
                Assert.Equal ( "The supplied consumer key has been black-listed due to complaints." , report.ProblemAdvice );
            }

            [Fact]
            public void ToString_GivenFormattedParameterAbsentProblem_ShouldBeEqual ( )
            {
                // Arrange.
                string formatted = "oauth_problem=parameter_absent&oauth_parameters_absent=oauth_nonce";

                // Act.
                var report = new OAuthProblemReport ( formatted );

                // Assert.
                Assert.Equal ( OAuthProblems.ParameterAbsent , report.Problem );
                Assert.NotNull ( report.ParametersAbsent );
                Assert.Contains ( Parameters.OAuth_Nonce , report.ParametersAbsent );
            }

            [Fact]
            public void ToString_GivenFormattedParameterRejectedProblem_ShouldBeEqual ( )
            {
                // Arrange.
                string formatted = "oauth_problem=parameter_rejected&oauth_parameters_rejected=oauth_timestamp";

                // Act.
                var report = new OAuthProblemReport ( formatted );

                // Assert.
                Assert.Equal ( OAuthProblems.ParameterRejected , report.Problem );
                Assert.NotNull ( report.ParametersRejected );
                Assert.Contains ( Parameters.OAuth_Timestamp , report.ParametersRejected );
            }

            [Fact]
            public void ToString_GivenFormattedTimestampRefusedProblem_ShouldBeEqual ( )
            {
                // Arrange.
                var fromTimestamp = new DateTime ( 2008 , 1 , 1 );
                long fromTimestampEpoch = fromTimestamp.Epoch ( );

                var toTimestamp = new DateTime ( 2009 , 1 , 1 );
                long toStampEpoch = toTimestamp.Epoch ( );

                string formatted = $"oauth_problem=timestamp_refused&oauth_acceptable_timestamps={fromTimestampEpoch}-{toStampEpoch}";

                // Act.
                var report = new OAuthProblemReport ( formatted );

                // Assert.
                Assert.Equal ( OAuthProblems.TimestampRefused , report.Problem );
                Assert.Equal ( fromTimestamp , report.AcceptableTimeStampsFrom );
                Assert.Equal ( toTimestamp , report.AcceptableTimeStampsTo );
            }

            [Fact]
            public void ToString_GivenFormattedVersionRejectedProblem_ShouldBeEqual ( )
            {
                // Arrange.
                string formatted = "oauth_problem=version_rejected&oauth_acceptable_versions=1.0-2.0";

                // Act.
                var report = new OAuthProblemReport ( formatted );

                // Assert.
                Assert.Equal ( OAuthProblems.VersionRejected , report.Problem );
                Assert.Equal ( "1.0" , report.AcceptableVersionFrom );
                Assert.Equal ( "2.0" , report.AcceptableVersionTo );
            }

            [Fact]
            public void ToString_GivenUnformattedConsumerKeyRefusedProblem_ShouldBeEqual ( )
            {
                // Arrange.
                var report = new OAuthProblemReport
                {
                    Problem = OAuthProblems.ConsumerKeyRefused ,
                    ProblemAdvice = "The supplied consumer key has been black-listed due to complaints."
                };

                string expected = "oauth_problem=consumer_key_refused&oauth_problem_advice=The%20supplied%20consumer%20key%20has%20been%20black-listed%20due%20to%20complaints.";

                // Act.
                string actual = report.ToString ( );

                // Assert.
                Assert.Equal ( expected , actual );
            }

            [Fact]
            public void ToString_GivenUnformattedParameterAbsentProblem_ShouldBeEqual ( )
            {
                // Arrange.
                var report = new OAuthProblemReport
                {
                    Problem = OAuthProblems.ParameterAbsent ,
                    ParametersAbsent = [ Parameters.OAuth_Nonce ]
                };

                string expected = "oauth_problem=parameter_absent&oauth_parameters_absent=oauth_nonce";

                // Act.
                string actual = report.ToString ( );

                // Assert.
                Assert.Equal ( expected , actual );
            }

            [Fact]
            public void ToString_GivenUnformattedParameterRejectedProblem_ShouldBeEqual ( )
            {
                // Arrange.
                var report = new OAuthProblemReport
                {
                    Problem = OAuthProblems.ParameterRejected ,
                    ParametersRejected = [ Parameters.OAuth_Timestamp ]
                };

                string expected = "oauth_problem=parameter_rejected&oauth_parameters_rejected=oauth_timestamp";

                // Act.
                string actual = report.ToString ( );

                // Assert.
                Assert.Equal ( expected , actual );
            }

            [Fact]
            public void ToString_GivenUnformattedTimestampRefusedProblem_ShouldBeEqual ( )
            {
                // Arrange.
                var fromTimestamp = new DateTime ( 2008 , 1 , 1 );
                long fromTimestampEpoch = fromTimestamp.Epoch ( );

                var toTimestamp = new DateTime ( 2009 , 1 , 1 );
                long toStampEpoch = toTimestamp.Epoch ( );

                var report = new OAuthProblemReport
                {
                    Problem = OAuthProblems.TimestampRefused ,
                    AcceptableTimeStampsFrom = fromTimestamp ,
                    AcceptableTimeStampsTo = toTimestamp
                };

                string expected = $"oauth_problem=timestamp_refused&oauth_acceptable_timestamps={fromTimestampEpoch}-{toStampEpoch}";

                // Act.
                string actual = report.ToString ( );

                // Assert.
                Assert.Equal ( expected , actual );
            }

            [Fact]
            public void ToString_GivenUnformattedVersionRejectedProblem_ShouldBeEqual ( )
            {
                // Arrange.
                var report = new OAuthProblemReport
                {
                    Problem = OAuthProblems.VersionRejected ,
                    AcceptableVersionFrom = "1.0" ,
                    AcceptableVersionTo = "2.0"
                };

                string expected = "oauth_problem=version_rejected&oauth_acceptable_versions=1.0-2.0";

                // Act.
                string actual = report.ToString ( );

                // Assert.
                Assert.Equal ( expected , actual );
            }
        }

        public class UriUtilityTests
        {
            public class GetHeaderParametersTests
            {
                [Fact]
                public void GetHeaderParameters_GivenEncodedParameters_ShouldReturnAllParameters ( )
                {
                    // Arrange.
                    string encodedParameters = "OAuth realm=\"http:\\\\somerealm.com\", oauth_consumer_key=\"consumerKey\"";

                    // Act.
                    var parameters = UriUtility.GetHeaderParameters ( encodedParameters );

                    // Assert.
                    Assert.NotNull ( parameters );
                    Assert.Equal ( 2 , parameters.Count );
                    Assert.Equal ( "consumerKey" , parameters.Single ( p => p.Key == "oauth_consumer_key" ).Value );
                    Assert.Equal ( @"http:\\somerealm.com" , parameters.Single ( p => p.Key == "realm" ).Value );
                }

                [Fact]
                public void GetHeaderParameters_WhenAuthorizationHeaderDoesNotContainOAuth_ShouldReturnEmptyCollection ( )
                {
                    // Arrange.
                    string encodedParameters = "realm=\"http:\\somerealm.com\", oauth_consumer_key=\"\"";

                    // Act.
                    var parameters = UriUtility.GetHeaderParameters ( encodedParameters );

                    // Assert.
                    Assert.NotNull ( parameters );
                    Assert.Empty ( parameters );
                }

                [Fact]
                public void GetHeaderParameters_WhenKeysValueIsEmpty_ShouldReturnEmptyValue ( )
                {
                    // Arrange.
                    string encodedParameters = "OAuth realm=\"http:\\somerealm.com\", oauth_consumer_key=\"\"";

                    // Act.
                    var parameters = UriUtility.GetHeaderParameters ( encodedParameters );

                    // Assert.
                    Assert.NotNull ( parameters );
                    Assert.Equal ( "" , parameters.Single ( p => p.Key == "oauth_consumer_key" ).Value );
                }

                [Fact]
                public void GetQueryParameters_GivenEncodedParametersWithoutQuestionMark_ShouldReturnAllParameters ( )
                {
                    // Arrange.
                    string encodedParameters = "key1=value1&key2=value2";

                    // Act.
                    var parameters = UriUtility.GetQueryParameters ( encodedParameters );

                    // Assert.
                    Assert.NotNull ( parameters );
                    Assert.Equal ( 2 , parameters.Count );
                    Assert.Equal ( "value1" , parameters.Single ( p => p.Key == "key1" ).Value );
                    Assert.Equal ( "value2" , parameters.Single ( p => p.Key == "key2" ).Value );
                }

                [Fact]
                public void GetQueryParameters_GivenEncodedParametersWithQuestionMark_ShouldReturnAllParameters ( )
                {
                    // Arrange.
                    string encodedParameters = "?key1=value1&key2=value2";

                    // Act.
                    var parameters = UriUtility.GetQueryParameters ( encodedParameters );

                    // Assert.
                    Assert.NotNull ( parameters );
                    Assert.Equal ( 2 , parameters.Count );
                    Assert.Equal ( "value1" , parameters.Single ( p => p.Key == "key1" ).Value );
                    Assert.Equal ( "value2" , parameters.Single ( p => p.Key == "key2" ).Value );
                }
            }

            public class NormalizeRequestParamters
            {
                [Fact]
                public void NormalizeRequestParameters_GivenMultipleParameters_ShouldReturnParametersInOrdinalOrder ( )
                {
                    // Arrange.
                    var parameters = new Dictionary<string , string> { { "ZIP" , "123" } , { "CVV" , "123" } , { "ccid" , "123" } };
                    string expected = "CVV=123&ZIP=123&ccid=123";

                    // Act.
                    string actual = UriUtility.NormalizeRequestParameters ( parameters );

                    // Assert.
                    Assert.Equal ( expected , actual );
                }
            }

            public class ParseAuthorizationHeaderKeyValuePair
            {
                [Fact]
                public void ParseAuthorizationHeaderKeyValuePair_WhenSignatureContainsEqualSign_ShouldBeEqual ( )
                {
                    // Arrange.
                    string signatureInHeader = "auth_signature=\"uZF3aYQFtyK0F1FFHY+w7/Be+m4=\"";
                    string expected = "uZF3aYQFtyK0F1FFHY w7/Be m4=";

                    // Act.
                    var actual = UriUtility.ParseAuthorizationHeaderKeyValuePair ( signatureInHeader );

                    // Assert.
                    Assert.Equal ( "auth_signature" , actual.Key );
                    Assert.Equal ( expected , actual.Value );
                }
            }
        }
    }
}