using Azure.Security.KeyVault.Keys.Cryptography;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace OpenVsixSignTool.Core
{
    /// <summary>
    /// A signing context used for signing packages with Azure Key Vault Keys.
    /// </summary>
    public class SigningContext : ISigningContext
    {
        private readonly SignConfigurationSet _configuration;

        /// <summary>
        /// Creates a new siging context.
        /// </summary>
        public SigningContext(SignConfigurationSet configuration)
        {
            DateTimeOffset highNoon = new DateTimeOffset(2025, 3, 24, 12, 0, 1, TimeSpan.Zero);

            ContextCreationTime = DateTimeOffset.Now;

            // Archie - Not the normal Path.
            // This will validate that an Azure Signature has the same result as the same 
            // certificate signed locally will have the same result.
            //ContextCreationTime = highNoon;

            _configuration = configuration;
        }

        /// <summary>
        /// 
        /// </summary>
        public string TimestampServerUrl => _configuration.TimestampServerUrl;

        /// <summary>
        /// Gets the date and time that this context was created.
        /// </summary>
        public DateTimeOffset ContextCreationTime { get; }

        /// <summary>
        /// Gets the file digest algorithm.
        /// </summary>
        public HashAlgorithmName FileDigestAlgorithmName => _configuration.FileDigestAlgorithm;

        /// <summary>
        /// Gets the certificate and public key used to validate the signature.
        /// </summary>
        public X509Certificate2 Certificate => _configuration.PublicCertificate;

        /// <summary>
        /// Gets the signature algorithm.
        /// </summary>
        public SigningAlgorithm SignatureAlgorithm
        {
            get
            {
                if (_configuration.SigningKey == null && 
                    _configuration.AzureCryptoClient != null )
                {
                    return SigningAlgorithm.RSA;
                }
                switch (_configuration.SigningKey)
                {
                    case RSA _: return SigningAlgorithm.RSA;
                    case ECDsa _: return SigningAlgorithm.ECDSA;
                    default: return SigningAlgorithm.Unknown;
                }
            }
        }


        /// <summary>
        /// Gets the XmlDSig identifier for the configured algorithm.
        /// </summary>
        public Uri XmlDSigIdentifier => SignatureAlgorithmTranslator.SignatureAlgorithmToXmlDSigUri(
            SignatureAlgorithm, 
            _configuration.SignatureDigestAlgorithm);


        /// <summary>
        /// Signs a digest.
        /// </summary>
        /// <param name="digest">The digest to sign.</param>
        /// <returns>The signature of the digest.</returns>
        public byte[] SignDigest(byte[] digest)
        {
            if (_configuration.AzureCryptoClient != null)
            {
                SignResult signResult = AzureSign(digest).Result;

                return signResult.Signature;
            }
            else
            {
                switch (_configuration.SigningKey)
                {
                    case RSA rsa:
                        return rsa.SignHash(digest, _configuration.SignatureDigestAlgorithm, RSASignaturePadding.Pkcs1);
                    case ECDsa ecdsa:
                        return ecdsa.SignHash(digest);
                    default:
                        throw new InvalidOperationException("Unknown signing algorithm.");
                }
            }
        }

        private async Task<SignResult> AzureSign(byte[] digest)
        {
            SignResult result = null;

            string muck = _configuration.SignatureDigestAlgorithm.ToString().Replace("SHA", "RS");
            SignatureAlgorithm algorithm = new SignatureAlgorithm(muck);

            try
            {
                result = await _configuration.AzureCryptoClient.SignAsync(
                    algorithm, digest);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }

            return result;
        }

        /// <summary>
        /// Verifies a digest is valid given a signature.
        /// </summary>
        /// <param name="digest">The digest to validate.</param>
        /// <param name="signature">The signature to validate with.</param>
        /// <returns></returns>
        public bool VerifyDigest(byte[] digest, byte[] signature)
        {

            switch (SignatureAlgorithm)
            {
                case SigningAlgorithm.RSA:
                    using (var publicKey = Certificate.GetRSAPublicKey())
                    {
                        return publicKey.VerifyHash(digest, signature, _configuration.SignatureDigestAlgorithm, RSASignaturePadding.Pkcs1);
                    }
                case SigningAlgorithm.ECDSA:
                    using (var publicKey = Certificate.GetECDsaPublicKey())
                    {
                        return publicKey.VerifyHash(digest, signature);
                    }
                default:
                    throw new InvalidOperationException("Unknown signing algorithm.");
            }
        }
    }
}
