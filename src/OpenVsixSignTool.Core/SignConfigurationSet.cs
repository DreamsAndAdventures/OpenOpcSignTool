using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Keys;

namespace OpenVsixSignTool.Core
{
    /// <summary>
    /// A configuration set for a signing operation.
    /// </summary>
    public sealed class SignConfigurationSet
    {
        /// <summary>
        /// Creates a new instance of the <see cref="SignConfigurationSet"/>.
        /// </summary>
        /// <param name="fileDigestAlgorithm">The <see cref="HashAlgorithmName"/> used to digest files.</param>
        /// <param name="signatureDigestAlgorithm">The <see cref="HashAlgorithmName"/> used in signatures.</param>
        /// <param name="signingKey">An <see cref="AsymmetricAlgorithm"/> with a private key that is used to perform signing operations.</param>
        /// <param name="publicCertificate">An <see cref="X509Certificate2"/> that contains the public key and certificate used to embed in the signature.</param>
        public SignConfigurationSet(HashAlgorithmName fileDigestAlgorithm, HashAlgorithmName signatureDigestAlgorithm, AsymmetricAlgorithm signingKey, X509Certificate2 publicCertificate)
        {
            FileDigestAlgorithm = fileDigestAlgorithm;
            SignatureDigestAlgorithm = signatureDigestAlgorithm;
            SigningKey = signingKey;
            PublicCertificate = publicCertificate;
            Valid = true;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="fileDigestAlgorithm"></param>
        /// <param name="signatureDigestAlgorithm"></param>
        /// <param name="vaultUrl"></param>
        /// <param name="objectName"></param>
        /// <param name="certificate"></param>
        public SignConfigurationSet(
            HashAlgorithmName fileDigestAlgorithm,
            HashAlgorithmName signatureDigestAlgorithm,
            string vaultUrl,
            string objectName,
            bool certificate)
        {
            FileDigestAlgorithm = fileDigestAlgorithm;
            SignatureDigestAlgorithm = signatureDigestAlgorithm;

            AzureSetup(vaultUrl, objectName, certificate).Wait();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="vaultUrl"></param>
        /// <param name="objectName"></param>
        /// <param name="certificate"></param>
        /// <returns></returns>
        public async Task AzureSetup(string vaultUrl,
            string objectName,
            bool certificate)
        {
            Valid = false;

            try
            {
                DefaultAzureCredential credential = new DefaultAzureCredential();

                if (certificate)
                {
                    CertificateClient azureCertificateClient = new CertificateClient(
                        new Uri(vaultUrl), credential);
                    KeyVaultCertificateWithPolicy withPolicy = 
                        await azureCertificateClient.GetCertificateAsync(objectName);
                    byte[] certificateBytes = withPolicy.Cer;
                    PublicCertificate = new X509Certificate2(certificateBytes);
                    AzureCryptoClient = new CryptographyClient(withPolicy.KeyId, credential);

                    Valid = true;
                }
                else
                {
                    // Archie - Does not work until I know I can get a stripped certificate to create a hash
                    //var keyClient = new KeyClient(new Uri(vaultUrl), credential);

                    //KeyVaultKey key = await keyClient.GetKeyAsync(objectName);

                    //AzureCryptoClient = new CryptographyClient(key.Id, credential);

                    //Valid = true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        /// <summary>
        /// The <see cref="HashAlgorithmName"/> used to digest files.
        /// </summary>
        public HashAlgorithmName FileDigestAlgorithm { get; }

        /// <summary>
        /// The <see cref="HashAlgorithmName"/> used in signatures.
        /// </summary>
        public HashAlgorithmName SignatureDigestAlgorithm { get; }

        /// <summary>
        /// An <see cref="AsymmetricAlgorithm"/> with a private key that is used to perform signing operations.
        /// </summary>
        public AsymmetricAlgorithm SigningKey { get; }

        /// <summary>
        /// An <see cref="X509Certificate2"/> that contains the public key and certificate used to embed in the signature.
        /// </summary>
        public X509Certificate2 PublicCertificate { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public CryptographyClient AzureCryptoClient { get; set; }



        /// <summary>
        /// 
        /// </summary>
        public bool Valid { get; set; }

        
    }
}
