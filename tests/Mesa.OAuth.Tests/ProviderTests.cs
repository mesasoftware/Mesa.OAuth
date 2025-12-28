namespace Mesa.OAuth.Tests
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using Mesa.OAuth.Consumer;
    using Mesa.OAuth.Consumer.Interfaces;
    using Mesa.OAuth.Framework;
    using Mesa.OAuth.Framework.Interfaces;
    using Mesa.OAuth.Framework.Signing;
    using Mesa.OAuth.Framework.Signing.Interfaces;
    using Mesa.OAuth.Provider;
    using Mesa.OAuth.Provider.Inspectors;
    using Mesa.OAuth.Storage.Interfaces;
    using Mesa.OAuth.Testing;
    using Moq;

    public class ProviderTests
    {
        public class InspectorsTests
        {
            public class InspectContextTests
            {
                public class BodyHashTests
                {
                    private const string EmptyBodyHash = "2jmj7l5rSw0yVb/vlWAYkK/YBwk=";

                    protected static BodyHashValidationInspector GetBodyHashValidationInspector ( )
                    {
                        return new BodyHashValidationInspector ( );
                    }

                    public class HmacSha1Tests
                    {
                        [Fact]
                        public void InspectContext_WhenBodyHasFormParameters_ShouldThrowOAuthExceptionWithMessage ( )
                        {
                            // Arrange.
                            var context = new OAuthContext
                            {
                                UseAuthorizationHeader = false ,
                                BodyHash = "1234" ,
                                SignatureMethod = SignatureMethod.HmacSha1
                            };

                            var inspector = GetBodyHashValidationInspector ( );
                            string expected = "Encountered unexpected oauth_body_hash value in form-encoded request";

                            // Act & Assert.
                            var exception = Assert.Throws<OAuthException> ( ( ) => inspector.InspectContext ( ProviderPhase.AccessProtectedResourceRequest , context ) );
                            Assert.Equal ( expected , exception.Message );
                        }

                        [Fact]
                        public void InspectContext_WhenBodyHashDoesNotMatch_ShouldNotThrowException ( )
                        {
                            // Arrange.
                            var context = new OAuthContext
                            {
                                UseAuthorizationHeader = true ,
                                BodyHash = "wrong" ,
                                SignatureMethod = SignatureMethod.HmacSha1
                            };

                            var inspector = GetBodyHashValidationInspector ( );
                            string expected = "Failed to validate body hash";

                            // Act & Assert.
                            var exception = Assert.Throws<OAuthException> ( ( ) => inspector.InspectContext ( ProviderPhase.AccessProtectedResourceRequest , context ) );
                            Assert.Equal ( expected , exception.Message );
                        }

                        [Fact]
                        public void InspectContext_WhenBodyHashIsNull_ShouldNotThrowException ( )
                        {
                            // Arrange.
                            var context = new OAuthContext
                            {
                                UseAuthorizationHeader = true ,
                                BodyHash = null ,
                                SignatureMethod = SignatureMethod.HmacSha1
                            };

                            var inspector = GetBodyHashValidationInspector ( );

                            // Act.
                            var exception = Record.Exception ( ( ) => inspector.InspectContext ( ProviderPhase.AccessProtectedResourceRequest , context ) );

                            // Assert.
                            Assert.Null ( exception );
                        }

                        [Fact]
                        public void InspectContext_WhenBodyHashMatches_ShouldNotThrowException ( )
                        {
                            // Arrange.
                            var context = new OAuthContext
                            {
                                UseAuthorizationHeader = true ,
                                BodyHash = EmptyBodyHash ,
                                SignatureMethod = SignatureMethod.HmacSha1
                            };

                            var inspector = GetBodyHashValidationInspector ( );

                            // Act.
                            var exception = Record.Exception ( ( ) => inspector.InspectContext ( ProviderPhase.AccessProtectedResourceRequest , context ) );

                            // Assert.
                            Assert.Null ( exception );
                        }
                    }

                    public class PlainTextTests
                    {
                        [Fact]
                        public void InspectContext_WhenSignatureMethodIsPlainText_ShouldNotThrow ( )
                        {
                            // Arrange.
                            var context = new OAuthContext
                            {
                                UseAuthorizationHeader = true ,
                                BodyHash = "wrong" ,
                                SignatureMethod = SignatureMethod.PlainText
                            };

                            var inspector = GetBodyHashValidationInspector ( );

                            // Act.
                            var exception = Record.Exception ( ( ) => inspector.InspectContext ( ProviderPhase.AccessProtectedResourceRequest , context ) );

                            // Assert.
                            Assert.Null ( exception );
                        }
                    }
                }

                public class ConsumerTests
                {
                    [Fact]
                    public void InspectContext_GivenInvalidConsumer_ShouldThrowOAuthExceptionWithMessage ( )
                    {
                        // Arrange
                        var consumerStoreMock = new Mock<IConsumerStore> ( MockBehavior.Strict );

                        var context = new OAuthContext { ConsumerKey = "key" };

                        consumerStoreMock.Setup ( s => s.IsConsumer ( It.Is<OAuthContext> ( c => ReferenceEquals ( c , context ) ) ) )
                            .Returns ( false );

                        var inspector = new ConsumerValidationInspector ( consumerStoreMock.Object );
                        string expected = "Unknown Consumer (Realm: , Key: key)";

                        // Act & Assert.
                        var exception = Assert.Throws<OAuthException> ( ( ) => inspector.InspectContext ( ProviderPhase.GrantRequestToken , context ) );
                        Assert.Equal ( expected , exception.Message );
                        consumerStoreMock.Verify ( s => s.IsConsumer ( It.IsAny<OAuthContext> ( ) ) , Times.Once );
                    }

                    [Fact]
                    public void InspectContext_GivenValidConsumer_ShouldNotThrowException ( )
                    {
                        // Arrange
                        var consumerStoreMock = new Mock<IConsumerStore> ( MockBehavior.Strict );
                        var context = new OAuthContext { ConsumerKey = "key" };

                        consumerStoreMock.Setup ( s => s.IsConsumer ( It.Is<OAuthContext> ( c => ReferenceEquals ( c , context ) ) ) )
                            .Returns ( true );

                        var inspector = new ConsumerValidationInspector ( consumerStoreMock.Object );

                        // Act.
                        var exception = Record.Exception ( ( ) => inspector.InspectContext ( ProviderPhase.GrantRequestToken , context ) );

                        // Assert.
                        Assert.Null ( exception );
                        consumerStoreMock.Verify ( s => s.IsConsumer ( It.IsAny<OAuthContext> ( ) ) , Times.Once );
                    }
                }

                public class NonceTests
                {
                    [Fact]
                    public void InspectContext_GivenAlreadyUsedNonce_ShouldThrowOAuthExceptionWithMessage ( )
                    {
                        // Arrange.
                        var nonceStoreMock = new Mock<INonceStore> ( );

                        var context = new OAuthContext { Nonce = "1" };

                        nonceStoreMock.Setup ( x => x.RecordNonceAndCheckIsUnique ( context , "1" ) )
                            .Returns ( false );

                        var inspector = new NonceStoreInspector ( nonceStoreMock.Object );
                        string expected = "The nonce value \"1\" has already been used";

                        // Act & Assert.
                        var exception = Assert.Throws<OAuthException> ( ( ) => inspector.InspectContext ( ProviderPhase.GrantRequestToken , context ) );
                        Assert.Equal ( expected , exception.Message );
                    }

                    [Fact]
                    public void InspectContext_GivenUniqueNonce_ShouldNotThrowException ( )
                    {
                        // Arrange.
                        var nonceStoreMock = new Mock<INonceStore> ( );

                        var context = new OAuthContext { Nonce = "2" };

                        nonceStoreMock.Setup ( x => x.RecordNonceAndCheckIsUnique ( context , "2" ) )
                            .Returns ( true );

                        var inspector = new NonceStoreInspector ( nonceStoreMock.Object );

                        // Act.
                        var exception = Record.Exception ( ( ) => inspector.InspectContext ( ProviderPhase.GrantRequestToken , context ) );

                        // Assert.
                        Assert.Null ( exception );
                    }
                }

                public class SignatureTests
                {
                    [Fact]
                    public void InspectContext_GivenInvalidSignature_ShouldThrowOAuthExceptionWithMessage ( )
                    {
                        // Arrange.
                        var consumerStore = new Mock<IConsumerStore> ( MockBehavior.Loose );

                        var signer = new Mock<IOAuthContextSigner> ( MockBehavior.Strict );

                        var context = new OAuthContext
                        {
                            ConsumerKey = "key" ,
                            SignatureMethod = SignatureMethod.PlainText
                        };

                        signer.Setup ( s => s.ValidateSignature ( It.IsAny<OAuthContext> ( ) , It.IsAny<SigningContext> ( ) ) )
                            .Returns ( false );

                        var inspector = new SignatureValidationInspector ( consumerStore.Object , signer.Object );

                        string expected = "Failed to validate signature";

                        // Act & Assert.
                        var exception = Assert.Throws<OAuthException> ( ( ) => inspector.InspectContext ( ProviderPhase.GrantRequestToken , context ) );

                        Assert.Equal ( expected , exception.Message );
                        signer.Verify ( s => s.ValidateSignature ( It.IsAny<OAuthContext> ( ) , It.IsAny<SigningContext> ( ) ) , Times.Once );
                    }

                    public class CertificateTests
                    {
                        [Fact]
                        public void InspectContext_GivenPlainTextSignedContext_ShouldNotFetchCertificate ( )
                        {
                            // Arrange.
                            var consumerStoreMock = new Mock<IConsumerStore> ( MockBehavior.Strict );

                            var signerMock = new Mock<IOAuthContextSigner> ( MockBehavior.Strict );

                            var context = new OAuthContext
                            {
                                ConsumerKey = "key" ,
                                SignatureMethod = SignatureMethod.PlainText
                            };

                            consumerStoreMock.Setup ( x => x.GetConsumerSecret ( context ) )
                                .Returns ( "secret" );

                            signerMock.Setup ( s => s.ValidateSignature ( It.IsAny<OAuthContext> ( ) , It.IsAny<SigningContext> ( ) ) )
                                .Returns ( true );

                            var inspector = new SignatureValidationInspector ( consumerStoreMock.Object , signerMock.Object );

                            // Act.
                            var exception = Record.Exception ( ( ) => inspector.InspectContext ( ProviderPhase.GrantRequestToken , context ) );

                            // Assert.
                            Assert.Null ( exception );
                            consumerStoreMock.Verify ( x => x.GetConsumerSecret ( context ) , Times.Once );
                            consumerStoreMock.VerifyNoOtherCalls ( );
                            signerMock.Verify ( s => s.ValidateSignature ( It.IsAny<OAuthContext> ( ) , It.IsAny<SigningContext> ( ) ) , Times.Once );
                            signerMock.VerifyNoOtherCalls ( );
                        }

                        [Fact]
                        public void InspectContext_GivenRsaSha1SignedContext_ShouldFetchCertificate ( )
                        {
                            // Arrange.
                            var consumerStoreMock = new Mock<IConsumerStore> ( MockBehavior.Loose );
                            var signerMock = new Mock<IOAuthContextSigner> ( MockBehavior.Strict );

                            var context = new OAuthContext
                            {
                                ConsumerKey = "key" ,
                                SignatureMethod = SignatureMethod.RsaSha1
                            };

                            var publicKey = TestCertificates.OAuthTestCertificate ( )
                                .GetRSAPublicKey ( );

                            ArgumentNullException.ThrowIfNull ( publicKey );

                            // Expect certificate fetch
                            consumerStoreMock.Setup ( s => s.GetConsumerPublicKey ( It.Is<OAuthContext> ( c => ReferenceEquals ( c , context ) ) ) )
                                .Returns ( publicKey );

                            // Expect signature validation
                            signerMock.Setup ( s => s.ValidateSignature ( It.IsAny<OAuthContext> ( ) , It.IsAny<SigningContext> ( ) ) )
                                .Returns ( true );

                            var inspector = new SignatureValidationInspector (
                                consumerStoreMock.Object ,
                                signerMock.Object );

                            // Act.
                            var exception = Record.Exception ( ( ) => inspector.InspectContext ( ProviderPhase.GrantRequestToken , context ) );

                            // Assert.
                            Assert.Null ( exception );
                            consumerStoreMock.Verify ( s => s.GetConsumerPublicKey ( It.Is<OAuthContext> ( c => ReferenceEquals ( c , context ) ) ) , Times.Once );
                            signerMock.Verify ( s => s.ValidateSignature ( It.IsAny<OAuthContext> ( ) , It.IsAny<SigningContext> ( ) ) , Times.Once );
                            signerMock.VerifyNoOtherCalls ( );
                        }

                        public class FriendsterTests
                        {
                            private const string friendsterCertificate = @"-----BEGIN CERTIFICATE-----
MIIC8TCCAdmgAwIBAgIIYAHv2LMwPmAwDQYJKoZIhvcNAQELBQAwGDEWMBQGA1UEAxMNTWVzYU9B
dXRoVGVzdDAeFw0yNTEyMjYyMjIzMTNaFw0yNjEyMjcyMjIzMTNaMBgxFjAUBgNVBAMTDU1lc2FP
QXV0aFRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6m2n/ux3h6YI8wWT7eAZ/
v2bOHHMYSu4BaFbp5qaqJ0ODkf3tVLU/GdAkfazsnZLe0ZBH3ms4Py+dR+WlZQjahgn9G4QjMkke
qak6F3qos+xyhgr5cWVwkp5dNPRKiEobXyL9jI5wEVkGJXdbjryA4dYWC+qH5e8qq0fS5F+MO2jN
el5mHOFyeykBCTjQnIlJjX9EBlvzWhius5RQqL6q2MUEl//c9tN4UADlJv+KUVdYRKGR0ePLTmAT
vJ1oDJynTeHwekMx57z7GUPgUuaNJH8ZZULe3Zqcloc+fy6boYDTHF7pjDkpXc1J0vTtCN2dupvm
MW28voJuS2pUxdHNAgMBAAGjPzA9MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMB0GA1Ud
DgQWBBT+Dk7tsuASyEocQ4MvjtopkIPNFDANBgkqhkiG9w0BAQsFAAOCAQEAjSvojJ7TNc9HkLYu
QwDup2yhPVXuLs+XV6PV5YbEK4jcGz1UNufKU7w7qEeFggbpS5sN2T8rx1eMlogvSf5+UlZlAwdT
A410cWjBLL9nflcg+AAoX7nj2tWoBMAH07RFc9EXEc6+N1PoW4+hKnxv/hdoM3JZmTXxxqrD2B0c
28nzyf0Gk5h66WQZaTggKITmnBzD2Y0nCwKEOIfybgrymEINmCQdze1u9rYWSuSE/6mKjaDnEnKF
snQc4N77dp/e7okWiv62WYl3tdmtJZTkxw9Aunw186aJT2UnI8bgDMjJ1CF+7fD/RC7H/e8twukv
7YBJ30DF09YxVmmSF9kG5w==
-----END CERTIFICATE-----";

                            protected static X509Certificate2 GetFriendsterCertificate ( )
                            {
#if NET8_0
                                return new X509Certificate2 ( Encoding.ASCII.GetBytes ( friendsterCertificate ) );
#else
                                return X509CertificateLoader.LoadCertificate ( Encoding.ASCII.GetBytes ( friendsterCertificate ) );
#endif
                            }

                            public class UriTests
                            {
                                public class GenerateSignatureBaseTests
                                {
                                    [Fact]
                                    public void GenerateSignatureBase_GivenUriWithoutTrailingAmpersand_ShouldBeEqual ( )
                                    {
                                        // Arrange.
                                        string expected = "GET&http%3A%2F%2Fdemo.mesa.com%2FOpenSocial%2FHelloWorld.aspx&container%3Ddefault%26oauth_consumer_key%3Dfriendster.com%26oauth_nonce%3Dc39f4e3e6c309988763eb8af85fcb74b%26oauth_signature_method%3DRSA-SHA1%26oauth_timestamp%3D1221992254%26oauth_token%3D%26opensocial_app_id%3D52ae97f7aa8a7e7565dd40a4e00eb0f5%26opensocial_owner_id%3D82474146%26opensocial_viewer_id%3D82474146%26synd%3Dfriendster";

                                        var uri = new Uri (
                                            "http://demo.mesa.com/OpenSocial/HelloWorld.aspx?oauth_nonce=c39f4e3e6c309988763eb8af85fcb74b&oauth_timestamp=1221992254&oauth_consumer_key=friendster.com&synd=friendster&container=default&opensocial_owner_id=82474146&opensocial_viewer_id=82474146&opensocial_app_id=52ae97f7aa8a7e7565dd40a4e00eb0f5&oauth_token=&oauth_signature_method=RSA-SHA1&oauth_signature=KTh5TCW7Bcfp%2Bn8DuSlfWR7MepVr0WkMm5IjjlR%2Bo6AikkuHXRcN3aemyue3P5xKS2qX74wj4QWDF1KIFbMFSHdh%2BdyPnwqsoRTgkF0NG%2BlxccQkLPi9UWMod2LwuMfdZ5fTTGhoptZbn7JU7MX53MasIfAqFw2e7mdFYqkpifSTDFnZvL3Yf1CC8XRw3HxHQsMjXNWkt10Ng%2Fon0SLn69rzgvsHKWxX3h8sYwTF%2FxAnkrR9RuEUMhnc1lcM%2B7hIttVkssfKgNoyYEGOz1QUNEIh9RBJ6AN%2FoF%2BCZKSLPaYGg3DD0UzENDKu60vn2bx7kzmVLZXJO4cLMXVgHjJFIg%3D%3D" );

                                        string method = "GET";

                                        var oauthContextBuilder = new OAuthContextBuilder ( )
                                            .FromUri ( method , uri );

                                        // Act.
                                        string actual = oauthContextBuilder.GenerateSignatureBase ( );

                                        // Assert.
                                        Assert.Equal ( expected , actual );
                                    }

                                    [Fact]
                                    public void GenerateSignatureBase_GivenUriWithTrailingAmpersand_ShouldBeEqual ( )
                                    {
                                        // Arrange.
                                        string expected = "GET&http%3A%2F%2Fdemo.mesa.com%2FOpenSocial%2FHelloWorld.aspx&container%3Ddefault%26oauth_consumer_key%3Dfriendster.com%26oauth_nonce%3Dc39f4e3e6c309988763eb8af85fcb74b%26oauth_signature_method%3DRSA-SHA1%26oauth_timestamp%3D1221992254%26oauth_token%3D%26opensocial_app_id%3D52ae97f7aa8a7e7565dd40a4e00eb0f5%26opensocial_owner_id%3D82474146%26opensocial_viewer_id%3D82474146%26synd%3Dfriendster";

                                        var uri = new Uri (
                                            "http://demo.mesa.com/OpenSocial/HelloWorld.aspx?oauth_nonce=c39f4e3e6c309988763eb8af85fcb74b&oauth_timestamp=1221992254&oauth_consumer_key=friendster.com&synd=friendster&container=default&opensocial_owner_id=82474146&opensocial_viewer_id=82474146&opensocial_app_id=52ae97f7aa8a7e7565dd40a4e00eb0f5&oauth_token=&oauth_signature_method=RSA-SHA1&oauth_signature=KTh5TCW7Bcfp%2Bn8DuSlfWR7MepVr0WkMm5IjjlR%2Bo6AikkuHXRcN3aemyue3P5xKS2qX74wj4QWDF1KIFbMFSHdh%2BdyPnwqsoRTgkF0NG%2BlxccQkLPi9UWMod2LwuMfdZ5fTTGhoptZbn7JU7MX53MasIfAqFw2e7mdFYqkpifSTDFnZvL3Yf1CC8XRw3HxHQsMjXNWkt10Ng%2Fon0SLn69rzgvsHKWxX3h8sYwTF%2FxAnkrR9RuEUMhnc1lcM%2B7hIttVkssfKgNoyYEGOz1QUNEIh9RBJ6AN%2FoF%2BCZKSLPaYGg3DD0UzENDKu60vn2bx7kzmVLZXJO4cLMXVgHjJFIg%3D%3D&" );

                                        string method = "GET";

                                        var oauthContextBuilder = new OAuthContextBuilder ( )
                                            .FromUri ( method , uri );

                                        // Act.
                                        string actual = oauthContextBuilder.GenerateSignatureBase ( );

                                        // Assert.
                                        Assert.Equal ( expected , actual );
                                    }
                                }

                                public class ValidateSignatureTests
                                {
                                    [Fact]
                                    public void ValidateSignature_GivenSignedUriWithTrailingAmpersand_ShouldBeTrue ( )
                                    {
                                        var uri =
                                            new Uri (
                                                "http://demo.mesa.com/OpenSocial/HelloWorld.aspx?oauth_nonce=c39f4e3e6c309988763eb8af85fcb74b&oauth_timestamp=1221992254&oauth_consumer_key=friendster.com&synd=friendster&container=default&opensocial_owner_id=82474146&opensocial_viewer_id=82474146&opensocial_app_id=52ae97f7aa8a7e7565dd40a4e00eb0f5&oauth_token=&oauth_signature_method=RSA-SHA1&oauth_signature=KTh5TCW7Bcfp%2Bn8DuSlfWR7MepVr0WkMm5IjjlR%2Bo6AikkuHXRcN3aemyue3P5xKS2qX74wj4QWDF1KIFbMFSHdh%2BdyPnwqsoRTgkF0NG%2BlxccQkLPi9UWMod2LwuMfdZ5fTTGhoptZbn7JU7MX53MasIfAqFw2e7mdFYqkpifSTDFnZvL3Yf1CC8XRw3HxHQsMjXNWkt10Ng%2Fon0SLn69rzgvsHKWxX3h8sYwTF%2FxAnkrR9RuEUMhnc1lcM%2B7hIttVkssfKgNoyYEGOz1QUNEIh9RBJ6AN%2FoF%2BCZKSLPaYGg3DD0UzENDKu60vn2bx7kzmVLZXJO4cLMXVgHjJFIg%3D%3D&" );

                                        var context = new OAuthContextBuilder ( ).FromUri ( "GET" , uri );
                                        var signer = new OAuthContextSigner ( );
                                        var signingContext = new SigningContext
                                        {
                                            Algorithm = GetFriendsterCertificate ( )
                                            .GetRSAPublicKey ( )
                                        };

                                        Assert.True ( signer.ValidateSignature ( context , signingContext ) );
                                    }

                                    [Fact]
                                    public void ValidateSignature_GivenSignedUriWithoutTrailingAmpersand_ShouldBeTrue ( )
                                    {
                                        var uri =
                                            new Uri (
                                                "http://demo.mesa.com/OpenSocial/HelloWorld.aspx?oauth_nonce=c39f4e3e6c309988763eb8af85fcb74b&oauth_timestamp=1221992254&oauth_consumer_key=friendster.com&synd=friendster&container=default&opensocial_owner_id=82474146&opensocial_viewer_id=82474146&opensocial_app_id=52ae97f7aa8a7e7565dd40a4e00eb0f5&oauth_token=&oauth_signature_method=RSA-SHA1&oauth_signature=KTh5TCW7Bcfp%2Bn8DuSlfWR7MepVr0WkMm5IjjlR%2Bo6AikkuHXRcN3aemyue3P5xKS2qX74wj4QWDF1KIFbMFSHdh%2BdyPnwqsoRTgkF0NG%2BlxccQkLPi9UWMod2LwuMfdZ5fTTGhoptZbn7JU7MX53MasIfAqFw2e7mdFYqkpifSTDFnZvL3Yf1CC8XRw3HxHQsMjXNWkt10Ng%2Fon0SLn69rzgvsHKWxX3h8sYwTF%2FxAnkrR9RuEUMhnc1lcM%2B7hIttVkssfKgNoyYEGOz1QUNEIh9RBJ6AN%2FoF%2BCZKSLPaYGg3DD0UzENDKu60vn2bx7kzmVLZXJO4cLMXVgHjJFIg%3D%3D" );

                                        var context = new OAuthContextBuilder ( ).FromUri ( "GET" , uri );
                                        var signer = new OAuthContextSigner ( );
                                        var signingContext = new SigningContext
                                        {
                                            Algorithm = GetFriendsterCertificate ( )
                                            .GetRSAPublicKey ( )
                                        };

                                        Assert.True ( signer.ValidateSignature ( context , signingContext ) );
                                    }
                                }
                            }

                            public class UrlTests
                            {
                                public class GenerateSignatureBaseTests
                                {
                                    [Fact]
                                    public void GenerateSignatureBase_GivenUrlWithoutTrailingAmpersand_ShouldBeEqual ( )
                                    {
                                        // Arrange.
                                        string expected = "GET&http%3A%2F%2Fdemo.mesa.com%2FOpenSocial%2FHelloWorld.aspx&container%3Ddefault%26oauth_consumer_key%3Dfriendster.com%26oauth_nonce%3Dc39f4e3e6c309988763eb8af85fcb74b%26oauth_signature_method%3DRSA-SHA1%26oauth_timestamp%3D1221992254%26oauth_token%3D%26opensocial_app_id%3D52ae97f7aa8a7e7565dd40a4e00eb0f5%26opensocial_owner_id%3D82474146%26opensocial_viewer_id%3D82474146%26synd%3Dfriendster%26xoauth_signature_publickey%3Dhttp%253A%252F%252Fwww.fmodules.com%252Fpublic080813.crt";
                                        string url = "http://demo.mesa.com/OpenSocial/HelloWorld.aspx?oauth_nonce=c39f4e3e6c309988763eb8af85fcb74b&oauth_timestamp=1221992254&oauth_consumer_key=friendster.com&synd=friendster&container=default&opensocial_owner_id=82474146&opensocial_viewer_id=82474146&opensocial_app_id=52ae97f7aa8a7e7565dd40a4e00eb0f5&oauth_token=&xoauth_signature_publickey=http%3A%2F%2Fwww.fmodules.com%2Fpublic080813.crt&oauth_signature_method=RSA-SHA1&oauth_signature=PLOkRKwLLeJRZz18PsAVQgL5y9Rdf0AW5eicdT0xwauRe3bE2NTDFHoMsUtO6UMHEY0v9GRcKbvkgEWEGGtiGA%3D%3D";

                                        var oauthContextBuilder = new OAuthContextBuilder ( ).FromUrl ( "GET" , url );

                                        // Act.
                                        string actual = oauthContextBuilder.GenerateSignatureBase ( );

                                        // Assert.
                                        Assert.Equal ( expected , actual );
                                    }

                                    [Fact]
                                    public void GenerateSignatureBase_GivenUrlWithTrailingAmpersand_ShouldBeEqual ( )
                                    {
                                        // Arrange.
                                        string expected = "GET&http%3A%2F%2Fdemo.mesa.com%2FOpenSocial%2FHelloWorld.aspx&container%3Ddefault%26oauth_consumer_key%3Dfriendster.com%26oauth_nonce%3Dc39f4e3e6c309988763eb8af85fcb74b%26oauth_signature_method%3DRSA-SHA1%26oauth_timestamp%3D1221992254%26oauth_token%3D%26opensocial_app_id%3D52ae97f7aa8a7e7565dd40a4e00eb0f5%26opensocial_owner_id%3D82474146%26opensocial_viewer_id%3D82474146%26synd%3Dfriendster%26xoauth_signature_publickey%3Dhttp%253A%252F%252Fwww.fmodules.com%252Fpublic080813.crt";
                                        string url = "http://demo.mesa.com/OpenSocial/HelloWorld.aspx?oauth_nonce=c39f4e3e6c309988763eb8af85fcb74b&oauth_timestamp=1221992254&oauth_consumer_key=friendster.com&synd=friendster&container=default&opensocial_owner_id=82474146&opensocial_viewer_id=82474146&opensocial_app_id=52ae97f7aa8a7e7565dd40a4e00eb0f5&oauth_token=&xoauth_signature_publickey=http%3A%2F%2Fwww.fmodules.com%2Fpublic080813.crt&oauth_signature_method=RSA-SHA1&oauth_signature=PLOkRKwLLeJRZz18PsAVQgL5y9Rdf0AW5eicdT0xwauRe3bE2NTDFHoMsUtO6UMHEY0v9GRcKbvkgEWEGGtiGA%3D%3D&";

                                        var oauthContextBuilder = new OAuthContextBuilder ( ).FromUrl ( "GET" , url );

                                        // Act.
                                        string actual = oauthContextBuilder.GenerateSignatureBase ( );

                                        // Assert.
                                        Assert.Equal ( expected , actual );
                                    }
                                }

                                public class ValidateSignatureTests
                                {
                                    [Fact]
                                    public void ValidateSignature_GivenSignedUrlWithTrailingAmpersand_ShouldBeTrue ( )
                                    {
                                        string url = "http://demo.mesa.com/OpenSocial/HelloWorld.aspx?oauth_nonce=c39f4e3e6c309988763eb8af85fcb74b&oauth_timestamp=1221992254&oauth_consumer_key=friendster.com&synd=friendster&container=default&opensocial_owner_id=82474146&opensocial_viewer_id=82474146&opensocial_app_id=52ae97f7aa8a7e7565dd40a4e00eb0f5&oauth_token=&oauth_signature_method=RSA-SHA1&oauth_signature=KTh5TCW7Bcfp%2Bn8DuSlfWR7MepVr0WkMm5IjjlR%2Bo6AikkuHXRcN3aemyue3P5xKS2qX74wj4QWDF1KIFbMFSHdh%2BdyPnwqsoRTgkF0NG%2BlxccQkLPi9UWMod2LwuMfdZ5fTTGhoptZbn7JU7MX53MasIfAqFw2e7mdFYqkpifSTDFnZvL3Yf1CC8XRw3HxHQsMjXNWkt10Ng%2Fon0SLn69rzgvsHKWxX3h8sYwTF%2FxAnkrR9RuEUMhnc1lcM%2B7hIttVkssfKgNoyYEGOz1QUNEIh9RBJ6AN%2FoF%2BCZKSLPaYGg3DD0UzENDKu60vn2bx7kzmVLZXJO4cLMXVgHjJFIg%3D%3D&";

                                        var context = new OAuthContextBuilder ( ).FromUrl ( "GET" , url );
                                        var signer = new OAuthContextSigner ( );
                                        var signingContext = new SigningContext
                                        {
                                            Algorithm = GetFriendsterCertificate ( )
                                                .GetRSAPublicKey ( )
                                        };

                                        Assert.True ( signer.ValidateSignature ( context , signingContext ) );
                                    }

                                    [Fact]
                                    public void ValidateSignature_GivenSignedUrlWithoutTrailingAmpersand_ShouldBeTrue ( )
                                    {
                                        string url = "http://demo.mesa.com/OpenSocial/HelloWorld.aspx?oauth_nonce=c39f4e3e6c309988763eb8af85fcb74b&oauth_timestamp=1221992254&oauth_consumer_key=friendster.com&synd=friendster&container=default&opensocial_owner_id=82474146&opensocial_viewer_id=82474146&opensocial_app_id=52ae97f7aa8a7e7565dd40a4e00eb0f5&oauth_token=&oauth_signature_method=RSA-SHA1&oauth_signature=KTh5TCW7Bcfp%2Bn8DuSlfWR7MepVr0WkMm5IjjlR%2Bo6AikkuHXRcN3aemyue3P5xKS2qX74wj4QWDF1KIFbMFSHdh%2BdyPnwqsoRTgkF0NG%2BlxccQkLPi9UWMod2LwuMfdZ5fTTGhoptZbn7JU7MX53MasIfAqFw2e7mdFYqkpifSTDFnZvL3Yf1CC8XRw3HxHQsMjXNWkt10Ng%2Fon0SLn69rzgvsHKWxX3h8sYwTF%2FxAnkrR9RuEUMhnc1lcM%2B7hIttVkssfKgNoyYEGOz1QUNEIh9RBJ6AN%2FoF%2BCZKSLPaYGg3DD0UzENDKu60vn2bx7kzmVLZXJO4cLMXVgHjJFIg%3D%3D";

                                        var context = new OAuthContextBuilder ( ).FromUrl ( "GET" , url );
                                        var signer = new OAuthContextSigner ( );
                                        var signingContext = new SigningContext
                                        {
                                            Algorithm = GetFriendsterCertificate ( )
                                                .GetRSAPublicKey ( )
                                        };

                                        Assert.True ( signer.ValidateSignature ( context , signingContext ) );
                                    }
                                }
                            }
                        }
                    }
                }

                public class TimeStampTests
                {
                    [Fact]
                    public void InspectContext_GivenInvalidDateAfterRange_ShouldThrowOAuthExceptionWithMessage ( )
                    {
                        // Arrange.
                        var inspector = new TimestampRangeInspector (
                            new TimeSpan ( 0 , 0 , 0 ) ,
                            new TimeSpan ( 1 , 0 , 0 ) ,
                            ( ) => new DateTime ( 2008 , 1 , 1 , 12 , 0 , 0 ) );

                        var context = new OAuthContext
                        {
                            Timestamp = new DateTime ( 2008 , 1 , 1 , 13 , 0 , 1 ).Epoch ( ).ToString ( )
                        };

                        string expected = "The timestamp is to far in the future, if must be at most 3600 seconds after the server current date and time";

                        // Act & Assert.
                        var exception = Assert.Throws<OAuthException> ( ( ) => inspector.InspectContext ( ProviderPhase.GrantRequestToken , context ) );
                        Assert.Equal ( expected , exception.Message );
                    }

                    [Fact]
                    public void InspectContext_GivenInvalidDateBeforeRange_ShouldThrowOAuthExceptionWithMessage ( )
                    {
                        // Arrange.
                        var inspector = new TimestampRangeInspector (
                            new TimeSpan ( 1 , 0 , 0 ) ,
                            new TimeSpan ( 0 , 0 , 0 ) ,
                            ( ) => new DateTime ( 2008 , 1 , 1 , 12 , 0 , 0 ) );

                        var context = new OAuthContext
                        {
                            Timestamp = new DateTime ( 2008 , 1 , 1 , 10 , 59 , 59 ).Epoch ( ).ToString ( )
                        };

                        string expected = "The timestamp is to old, it must be at most 3600 seconds before the servers current date and time";

                        // Act & Assert.
                        var exception = Assert.Throws<OAuthException> ( ( ) => inspector.InspectContext ( ProviderPhase.GrantRequestToken , context ) );
                        Assert.Equal ( expected , exception.Message );
                    }

                    [Fact]
                    public void InspectContext_GivenValidDateAfterRange_ShouldNotThrowException ( )
                    {
                        // Arrange.
                        var inspector = new TimestampRangeInspector (
                            new TimeSpan ( 0 , 0 , 0 ) ,
                            new TimeSpan ( 1 , 0 , 0 ) ,
                            ( ) => new DateTime ( 2008 , 1 , 1 , 12 , 0 , 0 ) );

                        var context = new OAuthContext
                        {
                            Timestamp = new DateTime ( 2008 , 1 , 1 , 13 , 0 , 0 ).Epoch ( ).ToString ( )
                        };

                        // Act.
                        var exception = Record.Exception ( ( ) => inspector.InspectContext ( ProviderPhase.GrantRequestToken , context ) );

                        // Assert.
                        Assert.Null ( exception );
                    }

                    [Fact]
                    public void InspectContext_GivenValidDateBeforeRange_ShouldNotThrowException ( )
                    {
                        // Arrange.
                        var inspector = new TimestampRangeInspector (
                            new TimeSpan ( 1 , 0 , 0 ) ,
                            new TimeSpan ( 0 , 0 , 0 ) ,
                            ( ) => new DateTime ( 2008 , 1 , 1 , 12 , 0 , 0 ) );

                        var context = new OAuthContext
                        {
                            Timestamp = new DateTime ( 2008 , 1 , 1 , 11 , 0 , 0 ).Epoch ( ).ToString ( )
                        };

                        // Act.
                        var exception = Record.Exception ( ( ) => inspector.InspectContext ( ProviderPhase.GrantRequestToken , context ) );

                        // Assert.
                        Assert.Null ( exception );
                    }
                }

                public class XAuthValidationTests
                {
                    [Fact]
                    public void InspectContext_GivenCorrectCredentials_ShouldNotThrowException ( )
                    {
                        // Arrange.
                        var context = new OAuthContext
                        {
                            XAuthMode = "client_auth" ,
                            XAuthUsername = "username" ,
                            XAuthPassword = "password"
                        };
                        var inspector = new XAuthValidationInspector ( ValidateXAuthMode , AuthenticateXAuthUsernameAndPassword );

                        // Act.
                        var exception = Record.Exception ( ( ) => inspector.InspectContext ( ProviderPhase.CreateAccessToken , context ) );

                        // Assert.
                        Assert.Null ( exception );
                    }

                    [Fact]
                    public void InspectContext_GivenEmptyPassword_ShouldThrowOAuthExceptionWithMessage ( )
                    {
                        // Arrange.
                        var context = new OAuthContext
                        {
                            XAuthMode = "client_auth" ,
                            XAuthUsername = "username"
                        };

                        var inspector = new XAuthValidationInspector ( ValidateXAuthMode , AuthenticateXAuthUsernameAndPassword );

                        string expected = "The x_auth_password parameter must be present";

                        // Act & Assert.
                        var ex = Assert.Throws<OAuthException> ( ( ) => inspector.InspectContext ( ProviderPhase.CreateAccessToken , context ) );
                        Assert.Equal ( expected , ex.Message );
                    }

                    [Fact]
                    public void InspectContext_GivenEmptyUserName_ShouldThrowOAuthExceptionWithMessage ( )
                    {
                        // Arrange.
                        var context = new OAuthContext
                        {
                            XAuthMode = "client_auth"
                        };

                        var inspector = new XAuthValidationInspector ( ValidateXAuthMode , AuthenticateXAuthUsernameAndPassword );

                        string expected = "The x_auth_username parameter must be present";

                        // Act & Assert.
                        var ex = Assert.Throws<OAuthException> ( ( ) => inspector.InspectContext ( ProviderPhase.CreateAccessToken , context ) );
                        Assert.Equal ( expected , ex.Message );
                    }

                    [Fact]
                    public void InspectContext_GivenEmptyXAuthMode_ShouldThrowOAuthExceptionWithMessage ( )
                    {
                        // Arrange.
                        var context = new OAuthContext
                        {
                            XAuthMode = string.Empty
                        };
                        var inspector = new XAuthValidationInspector ( ValidateXAuthMode , AuthenticateXAuthUsernameAndPassword );

                        string expected = "The x_auth_mode parameter must be present";

                        // Act & Assert.
                        var exception = Assert.Throws<OAuthException> ( ( ) => inspector.InspectContext ( ProviderPhase.CreateAccessToken , context ) );
                        Assert.Equal ( expected , exception.Message );
                    }

                    [Fact]
                    public void InspectContext_GivenInvalidXAuthMode_ShouldThrowOAuthExceptionWithMessage ( )
                    {
                        // Arrange.
                        var context = new OAuthContext
                        {
                            XAuthMode = "test_mode"
                        };

                        var inspector = new XAuthValidationInspector ( ValidateXAuthMode , AuthenticateXAuthUsernameAndPassword );

                        string expected = "The x_auth_mode parameter is invalid";

                        // Act & Assert.
                        var exception = Assert.Throws<OAuthException> ( ( ) => inspector.InspectContext ( ProviderPhase.CreateAccessToken , context ) );
                        Assert.Equal ( expected , exception.Message );
                    }

                    [Fact]
                    public void InspectContext_GivenWrongCredentials_ShouldThrowOAuthExceptionWithMessage ( )
                    {
                        // Arrange.
                        var context = new OAuthContext
                        {
                            XAuthMode = "client_auth" ,
                            XAuthUsername = "Joe" ,
                            XAuthPassword = "Bloggs"
                        };

                        var inspector = new XAuthValidationInspector ( ValidateXAuthMode , AuthenticateXAuthUsernameAndPassword );
                        string expected = "Authentication failed with the specified username and password";

                        // Act & Assert.
                        var exception = Assert.Throws<OAuthException> ( ( ) => inspector.InspectContext ( ProviderPhase.CreateAccessToken , context ) );
                        Assert.Equal ( expected , exception.Message );
                    }

                    private static bool AuthenticateXAuthUsernameAndPassword ( string username , string password )
                    {
                        return username == "username" && password == "password";
                    }

                    private static bool ValidateXAuthMode ( string authMode )
                    {
                        return authMode == "client_auth";
                    }
                }
            }
        }

        public class OAuthProvider10Tests
        {
            protected static OAuthProvider GetOAuthProvider ( )
            {
                var tokenStore = new TestTokenStore ( );
                var consumerStore = new TestConsumerStore ( );
                var nonceStore = new TestNonceStore ( );

                return new OAuthProvider (
                    tokenStore ,
                    new SignatureValidationInspector (
                        consumerStore ) ,
                    new NonceStoreInspector (
                        nonceStore ) ,
                    new TimestampRangeInspector (
                        new TimeSpan ( 1 , 0 , 0 ) ) ,
                    new ConsumerValidationInspector (
                        consumerStore ) ,
                    new XAuthValidationInspector (
                        ValidateXAuthMode ,
                        AuthenticateXAuthUsernameAndPassword ) );
            }

            protected static bool AuthenticateXAuthUsernameAndPassword ( string username , string password )
            {
                return username == "username" && password == "password";
            }

            protected static bool ValidateXAuthMode ( string authMode )
            {
                return authMode == "client_auth";
            }

            protected static IOAuthSession CreateConsumer ( string signatureMethod )
            {
                var consumerContext = new OAuthConsumerContext
                {
                    SignatureMethod = signatureMethod ,
                    ConsumerKey = "key" ,
                    ConsumerSecret = "secret" ,
                    Key = TestCertificates.OAuthTestCertificate ( )
                        .GetRSAPrivateKey ( )
                };

                var session = new OAuthSession (
                    consumerContext ,
                    "http://localhost/oauth/requesttoken.rails" ,
                    "http://localhost/oauth/userauhtorize.rails" ,
                    "http://localhost/oauth/accesstoken.rails" );

                return session;
            }

            public class AccessTokenTests
            {
                [Fact]
                public void AccessProtectedResourceRequest_GivenRsaSha1SignedConsumer_ShouldNotThrowException ( )
                {
                    // Arrange.
                    var session = CreateConsumer ( SignatureMethod.RsaSha1 );

                    session.AccessToken = new TokenBase
                    {
                        ConsumerKey = "key" ,
                        Token = "accesskey" ,
                        TokenSecret = "accesssecret"
                    };

                    var context = session.Request ( )
                        .Get ( )
                        .ForUrl (
                            "http://localhost/protected.rails" )
                        .SignWithToken ( )
                        .Context;

                    context.TokenSecret = null;

                    var provider = GetOAuthProvider ( );

                    // Act.
                    var exception = Record.Exception ( ( ) => provider.AccessProtectedResourceRequest ( context ) );

                    // Assert.
                    Assert.Null ( exception );
                }

                [Fact]
                public void AccessProtectedResourceRequest_GivenPlainTextSignedConsumer_ShouldNotThrowException ( )
                {
                    // Arrange.
                    var session = CreateConsumer ( SignatureMethod.PlainText );

                    session.AccessToken = new TokenBase
                    {
                        ConsumerKey = "key" ,
                        Token = "accesskey" ,
                        TokenSecret = "accesssecret"
                    };

                    var context = session.Request ( )
                        .Get ( )
                        .ForUrl (
                            "http://localhost/protected.rails" )
                        .SignWithToken ( )
                        .Context;

                    context.TokenSecret = null;

                    var provider = GetOAuthProvider ( );

                    // Act.
                    var exception = Record.Exception ( ( ) => provider.AccessProtectedResourceRequest ( context ) );

                    // Assert.
                    Assert.Null ( exception );
                }

                [Fact]
                public void CreateAccessToken_GivenHmacSha1SignedContext_ShouldBeEqual ( )
                {
                    // Arrange.
                    var session = CreateConsumer ( SignatureMethod.HmacSha1 );

                    var context = session.BuildAccessTokenContext (
                        "GET" ,
                        "client_auth" ,
                        "username" ,
                        "password" )
                        .Context;

                    context.TokenSecret = null;

                    var provider = GetOAuthProvider ( );

                    // Act.
                    var accessToken = provider.CreateAccessToken ( context );

                    // Assert.
                    Assert.Equal ( "accesskey" , accessToken.Token );
                    Assert.Equal ( "accesssecret" , accessToken.TokenSecret );
                }
            }

            public class RequestTokenTests
            {
                public class GrantRequestTokenTests
                {
                    [Fact]
                    public void GrantRequestToken_GivenHmacSha1SignedContext_ShouldBeEqual ( )
                    {
                        // Arrange.
                        var session = CreateConsumer ( SignatureMethod.HmacSha1 );

                        var context = session.BuildRequestTokenContext ( "GET" )
                            .Context;

                        var provider = GetOAuthProvider ( );

                        // Act.
                        var token = provider.GrantRequestToken ( context );

                        // Assert.
                        Assert.NotNull ( token );
                        Assert.Equal ( "requestkey" , token.Token );
                        Assert.Equal ( "requestsecret" , token.TokenSecret );
                    }

                    [Fact]
                    public void GrantRequestToken_GivenHmacSha1SignedContextWithInvalidSignature_ShouldThrowOAuthExceptionWithMessage ( )
                    {
                        // Arrange.
                        var session = CreateConsumer ( SignatureMethod.HmacSha1 );

                        var context = session.BuildRequestTokenContext ( "GET" )
                            .Context;

                        context.Signature = "wrong";

                        var provider = GetOAuthProvider ( );

                        string expected = "Failed to validate signature";

                        // Act.
                        var exception = Assert.Throws<OAuthException> ( ( ) => provider.GrantRequestToken ( context ) );

                        // Assert.
                        Assert.Equal ( expected , exception.Message );
                    }

                    [Fact]
                    public void GrantRequestToken_GivenPlainTextSignedContextWithInvalidConsumerKey_ShouldThrowOAuthExceptionWithMessage ( )
                    {
                        // Arrange.
                        var session = CreateConsumer ( SignatureMethod.PlainText );

                        session.ConsumerContext.ConsumerKey = "invalid";

                        var context = session.BuildRequestTokenContext ( "GET" )
                            .Context;

                        var provider = GetOAuthProvider ( );

                        string expected = "Unknown Consumer (Realm: , Key: invalid)";

                        // Act.
                        var exception = Assert.Throws<OAuthException> ( ( ) => provider.GrantRequestToken ( context ) );

                        // Assert.
                        Assert.Equal ( expected , exception.Message );
                    }

                    [Fact]
                    public void GrantRequestToken_GivenPlainTextSignedContext_ShouldBeEqual ( )
                    {
                        // Arrange.
                        var session = CreateConsumer ( SignatureMethod.PlainText );

                        var context = session.BuildRequestTokenContext ( "GET" )
                            .Context;

                        var provider = GetOAuthProvider ( );

                        // Act.
                        var token = provider.GrantRequestToken ( context );

                        // Assert.
                        Assert.NotNull ( token );
                        Assert.Equal ( "requestkey" , token.Token );
                        Assert.Equal ( "requestsecret" , token.TokenSecret );
                    }

                    [Fact]
                    public void GrantRequestToken_GivenRsaSha1SignedContext_ShouldBeEqual ( )
                    {
                        // Arrange.
                        var session = CreateConsumer ( SignatureMethod.RsaSha1 );

                        var context = session.BuildRequestTokenContext ( "GET" )
                            .Context;

                        var provider = GetOAuthProvider ( );

                        // Act.
                        var token = provider.GrantRequestToken ( context );

                        // Assert.
                        Assert.NotNull ( token );
                        Assert.Equal ( "requestkey" , token.Token );
                        Assert.Equal ( "requestsecret" , token.TokenSecret );
                    }

                    [Fact]
                    public void GrantRequestToken_GivenRsaSha1SignedContextWithInvalidSignature_ShouldThrowOAuthExceptionWithMessage ( )
                    {
                        // Arrange.
                        var session = CreateConsumer ( SignatureMethod.RsaSha1 );

                        var context = session.BuildRequestTokenContext ( "GET" )
                            .Context;

                        context.Signature = "eeh8hLNIlNNq1Xrp7BOCc+xgY/K8AmjxKNM7UdLqqcvNSmJqcPcf7yQIOvu8oj5R/mDvBpSb3+CEhxDoW23gggsddPIxNdOcDuEOenugoCifEY6nRz8sbtYt3GHXsDS2esEse/N8bWgDdOm2FRDKuy9OOluQuKXLjx5wkD/KYMY=";

                        var provider = GetOAuthProvider ( );

                        string expected = "Failed to validate signature";

                        // Act.
                        var exception = Assert.Throws<OAuthException> ( ( ) => provider.GrantRequestToken ( context ) );

                        // Assert.
                        Assert.Equal ( expected , exception.Message );
                    }
                }

                public class ExchangeRequestTokenForAccessTokenTests
                {
                    [Fact]
                    public void ExchangeRequestTokenForAccessToken_GivenRsaSha1SignedConsumer_ShouldBeEqual ( )
                    {
                        // Arrange.
                        var session = CreateConsumer ( SignatureMethod.RsaSha1 );

                        var context = session.BuildExchangeRequestTokenForAccessTokenContext (
                            new TokenBase
                            {
                                ConsumerKey = "key" ,
                                Token = "requestkey" ,
                                TokenSecret = "requestsecret"
                            } ,
                            "GET" ,
                            null )
                            .Context;

                        context.TokenSecret = null;

                        var provider = GetOAuthProvider ( );

                        // Act.
                        var accessToken = provider.ExchangeRequestTokenForAccessToken ( context );

                        // Assert.
                        Assert.NotNull ( accessToken );
                        Assert.Equal ( "accesskey" , accessToken.Token );
                        Assert.Equal ( "accesssecret" , accessToken.TokenSecret );
                    }

                    [Fact]
                    public void ExchangeRequestTokenForAccessToken_GivenPlainTextSignedConsumer_ShouldBeEqual ( )
                    {
                        // Arrange.
                        var session = CreateConsumer ( SignatureMethod.PlainText );

                        var context = session.BuildExchangeRequestTokenForAccessTokenContext (
                            new TokenBase
                            {
                                ConsumerKey = "key" ,
                                Token = "requestkey" ,
                                TokenSecret = "requestsecret"
                            } ,
                            "GET" ,
                            null )
                            .Context;

                        context.TokenSecret = null;

                        var provider = GetOAuthProvider ( );

                        // Act.
                        var accessToken = provider.ExchangeRequestTokenForAccessToken ( context );

                        // Assert.
                        Assert.NotNull ( accessToken );
                        Assert.Equal ( "accesskey" , accessToken.Token );
                        Assert.Equal ( "accesssecret" , accessToken.TokenSecret );
                    }

                    [Fact]
                    public void ExchangeRequestTokenForAccessToken_WhenVerifierMatch_ShouldNotThrowException ( )
                    {
                        // Arrange.
                        var session = CreateConsumer ( SignatureMethod.RsaSha1 );

                        var context = session.BuildExchangeRequestTokenForAccessTokenContext (
                            new TokenBase
                            {
                                ConsumerKey = "key" ,
                                Token = "requestkey"
                            } ,
                            "GET" ,
                            "GzvVb5WjWfHKa/0JuFupaMyn" )
                            .Context;

                        var provider = GetOAuthProvider ( );

                        // Act.
                        var exception = Record.Exception ( ( ) => provider.ExchangeRequestTokenForAccessToken ( context ) );

                        // Assert.
                        Assert.Null ( exception );
                    }

                    [Fact]
                    public void ExchangeRequestTokenForAccessToken_GivenContextWithTokenSecretParameter_ShouldThrowOAuthExceptionWithMessage ( )
                    {
                        // Arrange.
                        IOAuthContext context = new OAuthContext
                        {
                            TokenSecret = "secret"
                        };

                        var provider = GetOAuthProvider ( );

                        string expected = "The oauth_token_secret must not be transmitted to the provider.";

                        // Act.
                        var exception = Assert.Throws<OAuthException> ( ( ) => provider.ExchangeRequestTokenForAccessToken ( context ) );

                        // Assert.
                        Assert.Equal ( expected , exception.Message );
                    }
                }
            }
        }

        public class OAuthProvider10ATests
        {
            protected static IOAuthSession CreateConsumer ( string signatureMethod )
            {
                var consumerContext = new OAuthConsumerContext
                {
                    SignatureMethod = signatureMethod ,
                    ConsumerKey = "key" ,
                    ConsumerSecret = "secret" ,
                    Key = TestCertificates.OAuthTestCertificate ( )
                        .GetRSAPrivateKey ( )
                };

                var session = new OAuthSession (
                    consumerContext ,
                    "http://localhost/oauth/requesttoken.rails" ,
                    "http://localhost/oauth/userauhtorize.rails" ,
                    "http://localhost/oauth/accesstoken.rails" );

                return session;
            }

            protected static OAuthProvider GetOAuthProvider ( )
            {
                var tokenStore = new TestTokenStore ( );
                var consumerStore = new TestConsumerStore ( );
                var nonceStore = new TestNonceStore ( );

                return new OAuthProvider (
                    tokenStore ,
                    new SignatureValidationInspector (
                        consumerStore ) ,
                    new NonceStoreInspector (
                        nonceStore ) ,
                    new TimestampRangeInspector (
                        new TimeSpan ( 1 , 0 , 0 ) ) ,
                    new ConsumerValidationInspector (
                        consumerStore ) ,
                    new OAuth10AInspector (
                        tokenStore ) );
            }

            public class RequestTokenTests
            {
                public class ExchangeRequestTokenForAccessTokenTests
                {
                    [Fact]
                    public void ExchangeRequestTokenForAccessToken_GivenRsaSha1SignedContextWithInvalidVerifier_ShouldThrowOAuthExceptionWithMessage ( )
                    {
                        // Arrange.
                        var session = CreateConsumer ( SignatureMethod.RsaSha1 );

                        var context = session.BuildExchangeRequestTokenForAccessTokenContext (
                            new TokenBase
                            {
                                ConsumerKey = "key" ,
                                Token = "requestkey"
                            } ,
                            "GET" ,
                            "wrong" )
                            .Context;

                        var provider = GetOAuthProvider ( );

                        string expected = "The parameter \"oauth_verifier\" was rejected";

                        // Act.
                        var exception = Assert.Throws<OAuthException> ( ( ) => provider.ExchangeRequestTokenForAccessToken ( context ) );

                        // Assert.
                        Assert.Equal ( expected , exception.Message );
                    }

                    [Fact]
                    public void ExchangeRequestTokenForAccessToken_GivenRsaSha1SignedContextWithNullVerifier_ShouldThrowOAuthExceptionWithMessage ( )
                    {
                        // Arrange.
                        var session = CreateConsumer ( SignatureMethod.RsaSha1 );

                        var context = session.BuildExchangeRequestTokenForAccessTokenContext (
                            new TokenBase
                            {
                                ConsumerKey = "key" ,
                                Token = "requestkey"
                            } ,
                            "GET" ,
                            null )
                            .Context;

                        var provider = GetOAuthProvider ( );

                        string expected = "Missing required parameter : oauth_verifier";

                        // Act.
                        var exception = Assert.Throws<OAuthException> ( ( ) => GetOAuthProvider ( ).ExchangeRequestTokenForAccessToken ( context ) );

                        // Assert.
                        Assert.Equal ( expected , exception.Message );
                    }

                    [Fact]
                    public void ExchangeRequestTokenForAccessToken_GivenRsaSha1SignedContextWithValidVerifier_ShouldNotThrowException ( )
                    {
                        // Arrange.
                        var session = CreateConsumer ( SignatureMethod.RsaSha1 );

                        var context = session.BuildExchangeRequestTokenForAccessTokenContext (
                            new TokenBase
                            {
                                ConsumerKey = "key" ,
                                Token = "requestkey"
                            } ,
                            "GET" ,
                            "GzvVb5WjWfHKa/0JuFupaMyn" )
                            .Context;

                        var provider = GetOAuthProvider ( );

                        // Act.
                        var exception = Record.Exception ( ( ) => provider.ExchangeRequestTokenForAccessToken ( context ) );

                        // Assert.
                        Assert.Null ( exception );
                    }

                    [Fact]
                    public void GrantRequestToken_GivenPlainTextSignedContextWithoutCallbackUrl_ShouldNotThrowException ( )
                    {
                        // Arrange.
                        var session = CreateConsumer ( SignatureMethod.PlainText );

                        var context = session.BuildRequestTokenContext ( "GET" )
                            .Context;

                        var provider = GetOAuthProvider ( );

                        // Act.
                        var exception = Record.Exception ( ( ) => provider.GrantRequestToken ( context ) );

                        // Assert.
                        Assert.Null ( exception );
                    }
                }

                public class GrantRequestTokenTests
                {
                    [Fact]
                    public void GrantRequestToken_GivenPlainTextSignedContextWithNullCallbackUrl_ShouldThrowOAuthExceptionWithMessage ( )
                    {
                        // Arrange.
                        var session = CreateConsumer ( SignatureMethod.PlainText );

                        var context = session.BuildRequestTokenContext ( "GET" )
                            .Context;

                        context.CallbackUrl = null;

                        var provider = GetOAuthProvider ( );

                        string expected = "Missing required parameter : oauth_callback";

                        // Act.
                        var exception = Assert.Throws<OAuthException> ( ( ) => provider.GrantRequestToken ( context ) );

                        // Assert.
                        Assert.Equal ( expected , exception.Message );
                    }
                }
            }
        }
    }
}