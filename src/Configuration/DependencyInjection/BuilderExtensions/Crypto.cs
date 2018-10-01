// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using IdentityServer4.Stores;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json.Serialization;
using CryptoRandom = IdentityModel.CryptoRandom;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Builder extension methods for registering crypto services
    /// </summary>
    public static class IdentityServerBuilderExtensionsCrypto
    {
        /// <summary>
        /// Sets the signing credential.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="credential">The credential.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddSigningCredential(this IIdentityServerBuilder builder, SigningCredentials credential)
        {
            // todo dom
            if (!(credential.Key is AsymmetricSecurityKey || credential.Key is JsonWebKey jwk && jwk.HasPrivateKey))
            //&& !credential.Key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256Signature))
            {
                throw new InvalidOperationException("Signing key is not asymmetric");
            }

            builder.Services.AddSingleton<ISigningCredentialStore>(new DefaultSigningCredentialsStore(credential));
            builder.Services.AddSingleton<IValidationKeysStore>(new DefaultValidationKeysStore(new[] { credential.Key }));

            return builder;
        }

        /// <summary>
        /// Sets the signing credential.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="certificate">The certificate.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="InvalidOperationException">X509 certificate does not have a private key.</exception>
        /// <exception cref="InvalidOperationException">ECDSA key is not P-256, P-384, or P-521.</exception>
        public static IIdentityServerBuilder AddSigningCredential(this IIdentityServerBuilder builder, X509Certificate2 certificate)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));

            if (!certificate.HasPrivateKey)
            {
                throw new InvalidOperationException("X509 certificate does not have a private key.");
            }

            if (certificate.GetECDsaPrivateKey() is ECDsa ecdsa)
            {
                ValidateECDsaCurve(ecdsa);
                var algorithm = JwaFromECDsaSize(ecdsa.KeySize);
                var credential = new SigningCredentials(new X509SecurityKey(certificate), algorithm);
                return builder.AddSigningCredential(credential);
            }
            else
            {
                var credential = new SigningCredentials(new X509SecurityKey(certificate), "RS256");
                return builder.AddSigningCredential(credential);
            }
        }

        /// <summary>
        /// Sets the signing credential.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="name">The name.</param>
        /// <param name="location">The location.</param>
        /// <param name="nameType">Name parameter can be either a distinguished name or a thumbprint</param>
        /// <exception cref="InvalidOperationException">certificate: '{name}'</exception>
        public static IIdentityServerBuilder AddSigningCredential(this IIdentityServerBuilder builder, string name, StoreLocation location = StoreLocation.LocalMachine, NameType nameType = NameType.SubjectDistinguishedName)
        {
            var certificate = FindCertificate(name, location, nameType);
            if (certificate == null) throw new InvalidOperationException($"certificate: '{name}' not found in certificate store");

            return builder.AddSigningCredential(certificate);
        }

        /// <summary>
        /// Sets the signing credential.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="rsaKey">The RSA key.</param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException">RSA key does not have a private key.</exception>
        public static IIdentityServerBuilder AddSigningCredential(this IIdentityServerBuilder builder, RsaSecurityKey rsaKey)
        {
            if (rsaKey.PrivateKeyStatus == PrivateKeyStatus.DoesNotExist)
            {
                throw new InvalidOperationException("RSA key does not have a private key.");
            }

            var credential = new SigningCredentials(rsaKey, "RS256");
            return builder.AddSigningCredential(credential);
        }

        /// <summary>
        /// Sets the signing credential.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="ecdsaKey">The ECDSA key.</param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException">ECDSA key does not have a private key.</exception>
        /// <exception cref="InvalidOperationException">ECDSA key is not P-256, P-384, or P-521.</exception>
        public static IIdentityServerBuilder AddSigningCredential(this IIdentityServerBuilder builder, ECDsaSecurityKey ecdsaKey)
        {
            if (ecdsaKey.PrivateKeyStatus == PrivateKeyStatus.DoesNotExist)
            {
                throw new InvalidOperationException("ECDSA key does not have a private key.");
            }
            ValidateECDsaCurve(ecdsaKey.ECDsa);
            var algorithm = JwaFromECDsaSize(ecdsaKey.KeySize);
            var credential = new SigningCredentials(ecdsaKey, algorithm);
            return builder.AddSigningCredential(credential);
        }

        /// <summary>
        /// Sets the temporary signing credential.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="persistKey">Specifies if the temporary key should be persisted to disk.</param>
        /// <param name="filename">The filename.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddDeveloperSigningCredential(this IIdentityServerBuilder builder, bool persistKey = true, string filename = null)
        {
            if (filename == null)
            {
                filename = Path.Combine(Directory.GetCurrentDirectory(), "tempkey.rsa");
            }

            if (File.Exists(filename))
            {
                var keyFile = File.ReadAllText(filename);
                var tempKey = JsonConvert.DeserializeObject<TemporaryRsaKey>(keyFile, new JsonSerializerSettings { ContractResolver = new RsaKeyContractResolver() });

                return builder.AddSigningCredential(CreateRsaSecurityKey(tempKey.Parameters, tempKey.KeyId));
            }
            else
            {
                var key = CreateRsaSecurityKey();

                RSAParameters parameters;

                if (key.Rsa != null)
                    parameters = key.Rsa.ExportParameters(includePrivateParameters: true);
                else
                    parameters = key.Parameters;

                var tempKey = new TemporaryRsaKey
                {
                    Parameters = parameters,
                    KeyId = key.KeyId
                };

                if (persistKey)
                {
                    File.WriteAllText(filename, JsonConvert.SerializeObject(tempKey, new JsonSerializerSettings { ContractResolver = new RsaKeyContractResolver() }));
                }
                
                return builder.AddSigningCredential(key);
            }
        }

        /// <summary>
        /// Creates an RSA security key.
        /// </summary>
        /// <param name="parameters">The parameters.</param>
        /// <param name="id">The identifier.</param>
        /// <returns></returns>
        public static RsaSecurityKey CreateRsaSecurityKey(RSAParameters parameters, string id)
        {
            var key = new RsaSecurityKey(parameters)
            {
                KeyId = id
            };

            return key;
        }

        /// <summary>
        /// Creates a new ECDSA security key.
        /// </summary>
        /// <param name="parameters">The parameters.</param>
        /// <param name="id">The identifier.</param>
        /// <returns></returns>
        /// <exception cref="PlatformNotSupportedException">The platform does not support importing from ECDSA parameters.</exception>
        public static ECDsaSecurityKey CreateECDsaSecurityKey(ECParameters parameters, string id)
        {
            var ecdsa = ECDsa.Create();
            switch (ecdsa)
            {
                case ECDsaCng cng:
                    cng.ImportParameters(parameters);
                    break;
                case ECDsaOpenSsl ossl:
                    ossl.ImportParameters(parameters);
                    break;
                default:
                    throw new PlatformNotSupportedException();
            }
            ValidateECDsaCurve(ecdsa);
            return new ECDsaSecurityKey(ecdsa) { KeyId = id };
        }

        /// <summary>
        /// Creates a new RSA security key.
        /// </summary>
        /// <returns></returns>
        public static RsaSecurityKey CreateRsaSecurityKey()
        {
            var rsa = RSA.Create();
            RsaSecurityKey key;

            if (rsa is RSACryptoServiceProvider)
            {
                rsa.Dispose();
                var cng = new RSACng(2048);

                var parameters = cng.ExportParameters(includePrivateParameters: true);
                key = new RsaSecurityKey(parameters);
            }
            else
            {
                rsa.KeySize = 2048;
                key = new RsaSecurityKey(rsa);
            }

            key.KeyId = CryptoRandom.CreateUniqueId(16);
            return key;
        }

        /// <summary>
        /// Create a new ECDSA security key.
        /// </summary>
        /// <returns></returns>
        public static ECDsaSecurityKey CreateECDsaSecurityKey()
        {
            var ecdsa = ECDsa.Create();
            ecdsa.KeySize = 256;
            ValidateECDsaCurve(ecdsa);
            var key = new ECDsaSecurityKey(ecdsa)
            {
                KeyId = CryptoRandom.CreateUniqueId(16)
            };
            return key;
        }

        /// <summary>
        /// Adds the validation keys.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="keys">The keys.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddValidationKeys(this IIdentityServerBuilder builder, params AsymmetricSecurityKey[] keys)
        {
            builder.Services.AddSingleton<IValidationKeysStore>(new DefaultValidationKeysStore(keys));

            return builder;
        }

        /// <summary>
        /// Adds the validation key.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="certificate">The certificate.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static IIdentityServerBuilder AddValidationKey(this IIdentityServerBuilder builder, X509Certificate2 certificate)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));

            var key = new X509SecurityKey(certificate);
            return builder.AddValidationKeys(key);
        }

        /// <summary>
        /// Adds the validation key from the certificate store.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="name">The name.</param>
        /// <param name="location">The location.</param>
        /// <param name="nameType">Name parameter can be either a distinguished name or a thumbprint</param>
        public static IIdentityServerBuilder AddValidationKey(this IIdentityServerBuilder builder, string name, StoreLocation location = StoreLocation.LocalMachine, NameType nameType = NameType.SubjectDistinguishedName)
        {
            var certificate = FindCertificate(name, location, nameType);
            if (certificate == null) throw new InvalidOperationException($"certificate: '{name}' not found in certificate store");

            return builder.AddValidationKey(certificate);
        }

        private static X509Certificate2 FindCertificate(string name, StoreLocation location, NameType nameType)
        {
            X509Certificate2 certificate = null;

            if (location == StoreLocation.LocalMachine)
            {
                if (nameType == NameType.SubjectDistinguishedName)
                {
                    certificate = X509.LocalMachine.My.SubjectDistinguishedName.Find(name, validOnly: false).FirstOrDefault();
                }
                else if (nameType == NameType.Thumbprint)
                {
                    certificate = X509.LocalMachine.My.Thumbprint.Find(name, validOnly: false).FirstOrDefault();
                }
            }
            else
            {
                if (nameType == NameType.SubjectDistinguishedName)
                {
                    certificate = X509.CurrentUser.My.SubjectDistinguishedName.Find(name, validOnly: false).FirstOrDefault();
                }
                else if (nameType == NameType.Thumbprint)
                {
                    certificate = X509.CurrentUser.My.Thumbprint.Find(name, validOnly: false).FirstOrDefault();
                }
            }

            return certificate;
        }

        private static string JwaFromECDsaSize(int size)
        {
            switch (size)
            {
                case 256:
                    return "ES256";
                case 384:
                    return "ES384";
                case 521:
                    return "ES512";
                default:
                    throw new InvalidOperationException("Invalid ECDSA key size.");
            }
        }

        // used for serialization to temporary RSA key
        private class TemporaryRsaKey
        {
            public string KeyId { get; set; }
            public RSAParameters Parameters { get; set; }
        }

        private class RsaKeyContractResolver : DefaultContractResolver
        {
            protected override JsonProperty CreateProperty(MemberInfo member, MemberSerialization memberSerialization)
            {
                var property = base.CreateProperty(member, memberSerialization);

                property.Ignored = false;

                return property;
            }
        }

        // Validate the ECDSA curve to prevent invalid curve attacks and ensure we are using a NIST curve.
        private static void ValidateECDsaCurve(ECDsa ecdsa)
        {
            var curve = ecdsa.ExportParameters(false).Curve;
            curve.Validate();
            if (!curve.IsNamed)
            {
                throw new InvalidOperationException("Unnamed ECDSA curves are not supported.");
            }
            if (
                curve.Oid.FriendlyName != ECCurve.NamedCurves.nistP256.Oid.FriendlyName &&
                curve.Oid.FriendlyName != ECCurve.NamedCurves.nistP384.Oid.FriendlyName &&
                curve.Oid.FriendlyName != ECCurve.NamedCurves.nistP521.Oid.FriendlyName
            )
            {
                throw new InvalidOperationException("NIST P-256, P-384, and P-521 curves are only supported for ECDSA.");
            }
        }
    }

    /// <summary>
    /// Describes the string so we know what to search for in certificate store
    /// </summary>
    public enum NameType
    {
        /// <summary>
        /// subject distinguished name
        /// </summary>
        SubjectDistinguishedName,

        /// <summary>
        /// thumbprint
        /// </summary>
        Thumbprint
    }
}