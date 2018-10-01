// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Configuration;
using IdentityServer4.UnitTests.Common;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace IdentityServer4.UnitTests.Extensions
{
    public class IdentityServerBuilderExtensionsCryptoTests
    {

        [Fact]
        public void AddSigningCredential_with_json_web_key_containing_asymmetric_key_should_succeed()
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);

            String json =
            @"{
                ""alg"" : ""RS256"",
                ""kty"" : ""RSA"",
                ""use"" : ""sig"",
                ""d"" : ""KGGNkbbgm2hNMqW6fP1fmcWwEBy77WOJIPAXnDJ0KxNTtqDF8K5ULj7EElHO1A8ZnNl1Ey/x//G9lJCOQUU9wmj010dOSsW0NBbR5NtRtLLuVbkVdyft53PGeTQs+1S3c51fz9jojtNqmlfXSANPFOH6QhxmzpTx3KLsf/TpCzblkSrEGOOqCCvVdl7ybTcB230jNhh3JoL7po1rvxKtoOM4a/Bs0NtKj7e+VaHcf0GLnBPJYetsHu43ZfNejJeDoouaXZzeVEklY3B0pe10OTCIOu0JUKGZxNekklRIo1WSEYdL+CJfrSKWIv8bLj6xSr5zrASvWODyH443LN6ZvQ=="",
                ""e"" : ""AQAB"",
                ""n"" : ""q7mZfquRq8tzg/5slbNdQmrosNN/mFXS25dbSPm11qEDCgZa452KkO8+hvMtqa92QaqdlmalSF8+FRDOz3grDR5NtmnXZxuKnp+raKfzpC6hCvh2JSIe/J9enmsMM4YeI4d1FOSDwhJlZIYMdMnqG/VJtO1LSHjOaF3XN31ANKF0nPAsmr2/WysiQlxnxxiikLEnsFuNdS615ODDXFGTQ1E+zc4zVur4/Ox0cllPwHPA4PqoIgdPJPL+xM9IOIXuAGtsp4CYoxT6VWaRrALIZXXDY806WGTuctq4KKot6FGL9HQte2hRLl4E/r8SzIK86U3wRwrBe7saK+XUXoP0gQ="",
		        ""p"" :	""25dkucyCSqxRcJpRrhl7PXqw7wqBZeLQgYlZLpK493PdM8pFfq+/LK1hFtxIjdFKqXS/TOikB4YCBMEH0Im3HZ8Lo0dub3SWNhdegJyRjMbcoO+A9YSODEj7DFaNpZtdmtDi1n6etJm66ctPSR20NNpzoYZuaJ92fVQiKiOh6Qs="",
                ""q"" : ""yDKBrS8l1DOx4dwP9hdwhqZJ3XahidiIZSL7m46I/6+cjaki/1mtNiA60MOgqTKegP7Fo7jAYvliqQwnvVGmQvLv19cfKywlIuKN9DdkLHnKh75hfo7aakEbO7GJ5zVgsNnKOdf8wvpclfvIuRDEVva4cksPzsJy6K7C8ENCSCM="",
                ""dp"" :  ""GlYJ6o6wgawxCEQ5z5uWwETau5CS/Fk7kI2ceI14SZVHzlJQC2WglAcnQcqhmQCk57Xsy5iLM6vKyi8sdMJPh+nvR2HlyNA+w7YBy4L7odqn01VmLgv7zVVjZpNq4ZXEoDC1Q+xjtF1LoYaUt7wsRLp+a7znuPyHBXj1sAAeBwk="",
                ""dq"" :  ""W8OK3S83T8VCTBzq1Ap6cb3XLcQq11yBaJpYaj0zXr/IKsbUW+dnFeBAFWEWS3gAX3Bod1tAFB3rs0D3FjhO1XE1ruHUT520iAEAwGiDaj+JLh994NzqELo3GW2PoIM/BtFNeKYgHd9UgQsgPnQJCzOb6Aev/z3yHeW9RRQPVbE="",
                ""qi"" :  ""w4KdmiDN1GtK71JxaasqmEKPNfV3v2KZDXKnfyhUsdx/idKbdTVjvMOkxFPJ4FqV4yIVn06f3QHTm4NEG18Diqxsrzd6kXQIHOa858tLsCcmt9FoGfrgCFgVceh3K/Zah/r8rl9Y61u0Z1kZumwMvFpFE+mVU01t9HgTEAVkHTc="",
            }";

            JsonWebKey jsonWebKey = new JsonWebKey(json);
            SigningCredentials credentials = new SigningCredentials(jsonWebKey, jsonWebKey.Alg);
            identityServerBuilder.AddSigningCredential(credentials);
        }

        [Fact]
        public void AddSigningCredential_with_json_web_key_containing_symmetric_key_should_throw_exception()
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);

            String json =
            @"{
                ""alg"" : ""HS256"",
                ""kty"" : ""oct"",
                ""use"" : ""sig"",
                ""k"" : ""y5FHaQFtC294HLAtPXAcMkxZ5gHzCq24223vSYQUrDuu-3CUw7UzPru-AX30ubeB2IM_gUsNQ80bX22wwSk_3LC6XxYxqeGJZSeoQqHG0VNbaWCVkqeuB_HOiL1-ksPfGT-o8_A_Uv-6zi2NaEOYpnIyff5LpdW__LhiE-bhIenaw7GhoXSAfsGEZfNZpUUOU35NAiN2dv0T5vptb87wkL1I2zLhV0pdLvWsDWgQPINEa8bbCA_mseBYpB1eioZvt0TZbp6CL9tiEoiikYV_F3IutrJ2SOWYtDNFeQ3sbyYP7zTzh9a2eyaM8ca5_q3qosI92AbZ7WpEFLa9cZ_O7g""
            }";

            JsonWebKey jsonWebKey = new JsonWebKey(json);
            SigningCredentials credentials = new SigningCredentials(jsonWebKey, jsonWebKey.Alg);
            Assert.Throws<InvalidOperationException>(() => identityServerBuilder.AddSigningCredential(credentials));
        }

        [Fact]
        public void AddSigningCredential_with_json_web_key_ecdsa_nistP256_should_succeed()
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);

            String json =
            @"{
                ""alg"" : ""ES256"",
                ""kty"" : ""EC"",
                ""use"" : ""sig"",
                ""crv"" : ""P-256"",
                ""d"" : ""oAjf1PFB0ySHJJceZqno6r6LknnYmaL48LVyNnwFiyo"",
                ""x"" : ""0P2AoPh_fSK_W7-78zdx0iZmGRmEYe25FSiIM8YBGkg"",
                ""y"" : ""kZJgfvCcptgCgMojXzq3ZkTTFWUaOz0_F-vIekk8iPg""
            }";

            JsonWebKey jsonWebKey = new JsonWebKey(json);
            SigningCredentials credentials = new SigningCredentials(jsonWebKey, jsonWebKey.Alg);
            identityServerBuilder.AddSigningCredential(credentials);
        }

        [Fact]
        public void AddSigningCredential_with_json_web_key_ecdsa_nistP384_should_succeed()
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);

            String json =
            @"{
                ""alg"" : ""ES384"",
                ""kty"" : ""EC"",
                ""use"" : ""sig"",
                ""crv"" : ""P-384"",
                ""d"" : ""W3IIJN_QcZPbvLpnv3nGYLCG4eA14Q07bETJSyJ2j85S8K9pY6JWmZAlKk3SnMc1"",
                ""x"" : ""2WzN2ODrPj-fitccLClhkQe8lgsKU7EKpACLq6tj7RhS6Mei8F33I3VErZpnk8Qd"",
                ""y"" : ""tNz7nNmN48KZTwuFQ9YmFnvM6Wvxjpk3gaSLK9wU9zUOxNKtgaLKj1QUDW4_NH8Q""
            }";

            JsonWebKey jsonWebKey = new JsonWebKey(json);
            SigningCredentials credentials = new SigningCredentials(jsonWebKey, jsonWebKey.Alg);
            identityServerBuilder.AddSigningCredential(credentials);
        }

        [Fact]
        public void AddSigningCredential_with_json_web_key_ecdsa_nistP521_should_succeed()
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);

            String json =
            @"{
                ""alg"" : ""ES512"",
                ""kty"" : ""EC"",
                ""use"" : ""sig"",
                ""crv"" : ""P-521"",
                ""d"" : ""Aeky1OkS1KCAdvhjKtTg6Z3NAe8f2Y__Ejf0fkPoeElHLvHKASGMZYo2YMKfaU6tOl8CUZ0LlVykYfhWOWvpf5Fr"",
                ""x"" : ""AOb-4KVL6edrYD1H0fjII23B9shcb86eKpJNgbJDEU1FYCADyEl9n1mTOuvIXFsnyeueVJDFuv4vX_sr8ueVjTQ7"",
                ""y"" : ""AcDjVuSujpmfrEEv0RIXfdXiI5w9QztR1io4rfB5F4QPXthE159HweKPSjic-nabiI9MBPDMDPjt9Yve3OEj5B1e""
            }";

            JsonWebKey jsonWebKey = new JsonWebKey(json);
            SigningCredentials credentials = new SigningCredentials(jsonWebKey, jsonWebKey.Alg);
            identityServerBuilder.AddSigningCredential(credentials);
        }

        [Fact]
        public void AddSigningCredential_with_certificate_brainpoolp256r1_should_fail()
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);
            X509Certificate2 certificate = TestCert.LoadCertificate("brainpoolP256r1.pfx");
            var exception = Assert.Throws<InvalidOperationException>(() => {
                identityServerBuilder.AddSigningCredential(certificate);
            });
            Assert.Contains("NIST", exception.Message);
        }

        [Theory]
        [InlineData("nistP256.pfx")]
        [InlineData("nistP384.pfx")]
        [InlineData("nistP521.pfx")]
        public void AddSigningCredential_with_certificate_nist_curves_should_succeed(string certificateName)
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);
            X509Certificate2 certificate = TestCert.LoadCertificate(certificateName);
            identityServerBuilder.AddSigningCredential(certificate);
        }

        [Fact]
        public void AddDeveloperSigningCredential_should_succeed()
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);

            identityServerBuilder.AddDeveloperSigningCredential();

            //clean up... delete stored rsa key
            var filename = Path.Combine(Directory.GetCurrentDirectory(), "tempkey.rsa");

            if (File.Exists(filename))
                File.Delete(filename);
        }

        [Fact]
        public void AddDeveloperSigningCredential_should_succeed_when_called_multiple_times()
        {
            IServiceCollection services = new ServiceCollection();
            IIdentityServerBuilder identityServerBuilder = new IdentityServerBuilder(services);

            try
            {
                identityServerBuilder.AddDeveloperSigningCredential();
            
                //calling a second time will try to load the saved rsa key from disk. An exception will be throw if the private key is not serialized properly.
                identityServerBuilder.AddDeveloperSigningCredential();
            }
            finally
            {
                //clean up... delete stored rsa key
                var filename = Path.Combine(Directory.GetCurrentDirectory(), "tempkey.rsa");

                if (File.Exists(filename))
                    File.Delete(filename);
            }
        }
    }
}
