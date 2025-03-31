using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace OpenVsixSignTool.Core
{
    internal class XmlSignatureBuilder
    {
        private readonly XmlDocument _document;
        private readonly ISigningContext _signingContext;
        private readonly XmlElement _signatureElement;
        private XmlElement _objectElement;
        private XmlElement _xadesElement;
        public List<string> _output = new List<string>();
        private string DsPrefix;

        /// <summary>
        /// Creates a new signature with the correct namespace and empty root <c>Signature</c> element.
        /// </summary>
        internal XmlSignatureBuilder(ISigningContext signingContext, string dsPrefix)
        {
            _signingContext = signingContext;
            _document = new XmlDocument();
            var manager = new XmlNamespaceManager(_document.NameTable);
            manager.AddNamespace(dsPrefix, OpcKnownUris.XmlDSig.AbsoluteUri);
            manager.AddNamespace("xades", OpcKnownUris.XadesNamespace.AbsoluteUri);
            _signatureElement = CreateDSigElement("Signature");
            _document.AppendChild(_signatureElement);
            DsPrefix = dsPrefix;

        }

        private XmlElement CreateDSigElement(string name) => _document.CreateElement(DsPrefix, name, OpcKnownUris.XmlDSig.AbsoluteUri);
        private XmlElement CreateXadesElement(string name) => _document.CreateElement("xades", name, OpcKnownUris.XadesNamespace.AbsoluteUri);

        public XmlDocument BuildSignedXml()
        {
            if (_objectElement == null)
            {
                throw new InvalidOperationException("A manifest has not been set on the builder.");
            }
            if (_xadesElement == null)
            {
                throw new InvalidOperationException("Xades Timestamp has not been set on the builder.");
            }

            XmlDocument doc = new XmlDocument(_document.NameTable);
            XmlNode cloned = _signatureElement.Clone();
            cloned.AppendChild(_objectElement.Clone());
            doc.LoadXml(cloned.OuterXml);

            HashAlgorithmInfo hashAlgorithmInfo = new HashAlgorithmInfo(_signingContext.FileDigestAlgorithmName);
            HashAlgorithm hashAlgorithm = hashAlgorithmInfo.Create();

            SignedXml signedXml = InitializeSignedXml(_document, hashAlgorithmInfo, addXades:false);

            signedXml.ComputeSignature();
            XmlElement computed = signedXml.GetXml();

            XmlElement useSignature = CreateDSigElement("Signature");
            useSignature.InnerXml = computed.InnerXml;

            XmlElement keyInfoElement = BuildKeyInfoElement();

            _signatureElement.AppendChild(useSignature["SignedInfo"]);
            _signatureElement.AppendChild(keyInfoElement);
            _signatureElement.AppendChild(useSignature["SignatureValue"]);
            _signatureElement.AppendChild(_objectElement);


            return _document;
        }

        public SignedXml InitializeSignedXml(XmlDocument document, HashAlgorithmInfo hashAlgorithmInfo, bool addXades)
        {
            SignedXml signedXml = new SignedXml(document);

            RSA ensureExceptionIsThrown = null;
            //signedXml.SigningKey = ensureExceptionIsThrown;
            signedXml.SigningKey = _signingContext.Certificate.GetRSAPrivateKey();
            signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;//hashAlgorithmInfo.XmlDSigIdentifier.AbsoluteUri;
            signedXml.Signature.Id = "Signature-" + Guid.NewGuid().ToString();

            #region DataObjects 

            DataObject dataObject = new DataObject();
            dataObject.LoadXml(_objectElement);
            signedXml.AddObject(dataObject);

            if (addXades)
            {
                DataObject xadesObject = new DataObject();
                xadesObject.LoadXml(_xadesElement);
                signedXml.AddObject(xadesObject);
            }

            #endregion

            #region References

            Reference dataReference = new Reference()
            {
                Uri = "#" + GetObjectId(),
                Type = OpcKnownUris.XmlDSigObject.AbsoluteUri,
                DigestMethod = SignedXml.XmlDsigSHA256Url
            };

            signedXml.AddReference(dataReference);

            if (addXades)
            {
                Reference xadesReference = new Reference()
                {
                    Uri = "#" + GetSignedPropertiesId(),
                    Type = OpcKnownUris.XadesSignedProperties.AbsoluteUri,
                    DigestMethod = SignedXml.XmlDsigSHA256Url
                };

                signedXml.AddReference(xadesReference);
            }

            #endregion

            return signedXml;
        }

        private string GetSignedPropertiesId()
        {
            XmlElement qualifying = _xadesElement["xades:QualifyingProperties"];
            XmlElement signedProperties = qualifying["xades:SignedProperties"];
            return signedProperties.Attributes["Id"].Value;
        }

        private string GetObjectId()
        {
            return _objectElement.Attributes["Id"].Value;
        }


        public XmlDocument Build()
        {
            if (_objectElement == null)
            {
                throw new InvalidOperationException("A manifest has not been set on the builder.");
            }
            XmlElement keyInfoElement, signedInfo, signatureValue;
            var info = new HashAlgorithmInfo(_signingContext.FileDigestAlgorithmName);
            using (var canonicalHashAlgorithm = info.Create())
            {
                byte[] objectElementHash;
                string canonicalizationMethodObjectId;
                using (var objectElementCanonicalData = CanonicalizeElement(_objectElement, out canonicalizationMethodObjectId))
                {
                    objectElementHash = canonicalHashAlgorithm.ComputeHash(objectElementCanonicalData);
                }
                keyInfoElement = BuildKeyInfoElement();
                Stream signerInfoCanonicalStream;
                (signerInfoCanonicalStream, signedInfo) = BuildSignedInfoElement(
                    (_objectElement, objectElementHash, info.XmlDSigIdentifier.AbsoluteUri, canonicalizationMethodObjectId)
                );
                byte[] signerInfoElementHash;
                using (signerInfoCanonicalStream)
                {
                    signerInfoElementHash = canonicalHashAlgorithm.ComputeHash(signerInfoCanonicalStream);
                }
                signatureValue = BuildSignatureValue(signerInfoElementHash);
            }

            _signatureElement.AppendChild(signedInfo);
            _signatureElement.AppendChild(signatureValue);
            _signatureElement.AppendChild(keyInfoElement);
            _signatureElement.AppendChild(_objectElement);
            return _document;
        }

        private XmlElement BuildSignatureValue(byte[] signerInfoElementHash)
        {
            var signatureValueElement = CreateDSigElement("SignatureValue");
            signatureValueElement.InnerText = Convert.ToBase64String(_signingContext.SignDigest(signerInfoElementHash));
            return signatureValueElement;
        }

        private Stream CanonicalizeElement(XmlElement element, out string canonicalizationMethodUri, Action<string> setCanonicalization = null)
        {
            //The canonicalization transformer can't reasonable do just an element. It
            //seems content to do an entire XmlDocument.
            var transformer = new XmlDsigC14NTransform(false);
            setCanonicalization?.Invoke(transformer.Algorithm);

            var newDocument = new XmlDocument(_document.NameTable);
            newDocument.LoadXml(element.OuterXml);
            
            transformer.LoadInput(newDocument);

            var result = transformer.GetOutput(typeof(Stream));
            canonicalizationMethodUri = transformer.Algorithm;
            if (result is Stream s)
            {
                return s;
            }
            throw new NotSupportedException("Unable to canonicalize element.");
        }

        private (Stream, XmlElement) BuildSignedInfoElement(params (XmlElement element, byte[] canonicalDigest, string digestAlgorithm, string canonicalizationMethod)[] objects)
        {
            var signingIdentifier = _signingContext.XmlDSigIdentifier;

            var signedInfoElement = CreateDSigElement("SignedInfo");
            var canonicalizationMethodElement = CreateDSigElement("CanonicalizationMethod");
            var canonicalizationMethodAlgorithmAttribute = _document.CreateAttribute("Algorithm");
            canonicalizationMethodElement.Attributes.Append(canonicalizationMethodAlgorithmAttribute);

            var signatureMethodElement = CreateDSigElement("SignatureMethod");
            var signatureMethodAlgorithmAttribute = _document.CreateAttribute("Algorithm");
            signatureMethodAlgorithmAttribute.Value = signingIdentifier.AbsoluteUri;
            signatureMethodElement.Attributes.Append(signatureMethodAlgorithmAttribute);

            signedInfoElement.AppendChild(canonicalizationMethodElement);
            signedInfoElement.AppendChild(signatureMethodElement);

            foreach(var (element, digest, digestAlgorithm, method) in objects)
            {
                var idFromElement = element.GetAttribute("Id");
                var reference = "#" + idFromElement;

                var referenceElement = CreateDSigElement("Reference");
                var referenceUriAttribute = _document.CreateAttribute("URI");
                var referenceTypeAttribute = _document.CreateAttribute("Type");
                referenceUriAttribute.Value = reference;
                referenceTypeAttribute.Value = OpcKnownUris.XmlDSigObject.AbsoluteUri;

                referenceElement.Attributes.Append(referenceUriAttribute);
                referenceElement.Attributes.Append(referenceTypeAttribute);

                var referencesTransformsElement = CreateDSigElement("Transforms");
                var transformElement = CreateDSigElement("Transform");
                var transformAlgorithmAttribute = _document.CreateAttribute("Algorithm");
                transformAlgorithmAttribute.Value = method;
                transformElement.Attributes.Append(transformAlgorithmAttribute);
                referencesTransformsElement.AppendChild(transformElement);
                referenceElement.AppendChild(referencesTransformsElement);

                var digestMethodElement = CreateDSigElement("DigestMethod");
                var digestMethodAlgorithmAttribute = _document.CreateAttribute("Algorithm");
                digestMethodAlgorithmAttribute.Value = digestAlgorithm;
                digestMethodElement.Attributes.Append(digestMethodAlgorithmAttribute);
                referenceElement.AppendChild(digestMethodElement);

                var digestValueElement = CreateDSigElement("DigestValue");
                digestValueElement.InnerText = Convert.ToBase64String(digest);
                referenceElement.AppendChild(digestValueElement);

                signedInfoElement.AppendChild(referenceElement);
            }

            var canonicalSignerInfo = CanonicalizeElement(signedInfoElement, out _, c => canonicalizationMethodAlgorithmAttribute.Value = c);
            return (canonicalSignerInfo, signedInfoElement);
        }

        private XmlElement BuildKeyInfoElement()
        {
            var publicCertificate = Convert.ToBase64String(_signingContext.Certificate.Export(X509ContentType.Cert));
            var keyInfoElement = CreateDSigElement("KeyInfo");
            var x509DataElement = CreateDSigElement("X509Data");
            var x509CertificateElement = CreateDSigElement("X509Certificate");
            x509CertificateElement.InnerText = publicCertificate;
            x509DataElement.AppendChild(x509CertificateElement);
            keyInfoElement.AppendChild(x509DataElement);
            return keyInfoElement;
        }

        public void SetFileManifest(OpcSignatureManifest manifest)
        {
            var objectElement = CreateDSigElement("Object");
            var objectElementId = _document.CreateAttribute("Id");
            objectElementId.Value = "idPackageObject";
            objectElement.Attributes.Append(objectElementId);

            var manifestElement = CreateDSigElement("Manifest");

            foreach (var file in manifest.Manifest)
            {
                var referenceElement = CreateDSigElement("Reference");
                var referenceElementUriAttribute = _document.CreateAttribute("URI");
                referenceElementUriAttribute.Value = file.ReferenceUri.ToQualifiedPath();
                referenceElement.Attributes.Append(referenceElementUriAttribute);

                var digestMethod = CreateDSigElement("DigestMethod");
                var digestMethodAlgorithmAttribute = _document.CreateAttribute("Algorithm");
                digestMethodAlgorithmAttribute.Value = file.DigestAlgorithmIdentifier.AbsoluteUri;
                digestMethod.Attributes.Append(digestMethodAlgorithmAttribute);
                referenceElement.AppendChild(digestMethod);

                var digestValue = CreateDSigElement("DigestValue");
                digestValue.InnerText = System.Convert.ToBase64String(file.Digest);
                referenceElement.AppendChild(digestValue);


                manifestElement.AppendChild(referenceElement);
                objectElement.AppendChild(manifestElement);
            }

            var signaturePropertiesElement = CreateDSigElement("SignatureProperties");
            var signaturePropertyElement = CreateDSigElement("SignatureProperty");
            var signaturePropertyIdAttribute = _document.CreateAttribute("Id");
            var signaturePropertyTargetAttribute = _document.CreateAttribute("Target");
            signaturePropertyIdAttribute.Value = "idSignatureTime";
            signaturePropertyTargetAttribute.Value = "";

            signaturePropertyElement.Attributes.Append(signaturePropertyIdAttribute);
            signaturePropertyElement.Attributes.Append(signaturePropertyTargetAttribute);

            var signatureTimeElement = _document.CreateElement("SignatureTime", OpcKnownUris.XmlDigitalSignature.AbsoluteUri);
            var signatureTimeFormatElement = _document.CreateElement("Format", OpcKnownUris.XmlDigitalSignature.AbsoluteUri);
            var signatureTimeValueElement = _document.CreateElement("Value", OpcKnownUris.XmlDigitalSignature.AbsoluteUri);
            signatureTimeFormatElement.InnerText = "YYYY-MM-DDThh:mm:ss.sTZD";
            //signatureTimeValueElement.InnerText = _signingContext.ContextCreationTime.ToString("yyyy-MM-ddTHH:mm:ss.fzzz");
            signatureTimeValueElement.InnerText = "2024-10-23T15:26:04.3Z";

            signatureTimeElement.AppendChild(signatureTimeFormatElement);
            signatureTimeElement.AppendChild(signatureTimeValueElement);

            signaturePropertyElement.AppendChild(signatureTimeElement);
            signaturePropertiesElement.AppendChild(signaturePropertyElement);
            objectElement.AppendChild(signaturePropertiesElement);

            _objectElement = objectElement;
        }

        public void CreateXades()
        {
            byte[] certificateHash = _signingContext.Certificate.GetCertHash();
            string encodedHash = Convert.ToBase64String(certificateHash);

            // Now I can at least create the XAdES element.

            XmlElement digestMethod = CreateDSigElement("DigestMethod");
            XmlAttribute algorithm = _document.CreateAttribute("Algorithm");
            algorithm.Value = "http://www.w3.org/2001/04/xmlenc#sha256";
            digestMethod.Attributes.Append(algorithm);

            XmlElement digestValue = CreateDSigElement("DigestValue");
            digestValue.InnerText = encodedHash;

            XmlElement certDigest = CreateXadesElement("CertDigest");
            certDigest.AppendChild(digestMethod);
            certDigest.AppendChild(digestValue);

            XmlElement issuerNameElement = CreateDSigElement("X509IssuerName");
            issuerNameElement.InnerText = _signingContext.Certificate.IssuerName.Name;
            XmlElement issuerSerialNumber = CreateDSigElement("X509SerialNumber");
            issuerSerialNumber.InnerText = HexToDecimalString(_signingContext.Certificate.SerialNumber);

            XmlElement issuerSerial = CreateXadesElement("IssuerSerial");
            issuerSerial.AppendChild(issuerNameElement);
            issuerSerial.AppendChild(issuerSerialNumber);

            XmlElement cert = CreateXadesElement("Cert");
            cert.AppendChild(certDigest);
            cert.AppendChild(issuerSerial);

            XmlElement signingCertificate = CreateXadesElement("SigningCertificate");
            signingCertificate.AppendChild(cert);

            XmlElement signingTime = CreateXadesElement("SigningTime");
            string checkThis = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            string OldTime = _signingContext.ContextCreationTime.ToString("yyyy-MM-ddTHH:mm:ss.fzzz");
            DateTime utcForOffset = _signingContext.ContextCreationTime.UtcDateTime;
            string utcTime = utcForOffset.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            //signingTime.InnerText = _signingContext.ContextCreationTime.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            signingTime.InnerText = "2025-03-19T17:56:01.153Z";

            XmlElement signedSignatureProperties = CreateXadesElement("SignedSignatureProperties");
            signedSignatureProperties.AppendChild(signingTime);
            signedSignatureProperties.AppendChild(signingCertificate);

            XmlElement signedProperties = CreateXadesElement("SignedProperties");
            XmlAttribute signedPropertiesId = _document.CreateAttribute("Id");
            //signedPropertiesId.Value = "SignedProperties-" + Guid.NewGuid().ToString();
            signedPropertiesId.Value = "SignedProperties";
            signedProperties.Attributes.Append(signedPropertiesId);

            signedProperties.AppendChild(signedSignatureProperties);


            XmlElement qualifyingProperties = CreateXadesElement("QualifyingProperties");
            XmlAttribute target = _document.CreateAttribute("Target");
            target.Value = "#Signature-" + Guid.NewGuid().ToString();
            qualifyingProperties.Attributes.Append(target);
            qualifyingProperties.AppendChild(signedProperties);

            //XmlAttribute xadesVersion = _document.CreateAttribute("xadesv141");
            //xadesVersion.Value = "http://uri.etsi.org/01903/v1.4.1#";
            //qualifyingProperties.Attributes.Append(xadesVersion);

            _xadesElement = CreateDSigElement("Object");
            _xadesElement.AppendChild(qualifyingProperties);
        }

        private string HexToDecimalString(string hexString)
        {
            if (string.IsNullOrEmpty(hexString))
            {
                throw new ArgumentException("Hex string cannot be null or empty", nameof(hexString));
            }

            // Convert the hex string to a byte array
            byte[] bytes = Enumerable.Range(0, hexString.Length)
                                     .Where(x => x % 2 == 0)
                                     .Select(x => Convert.ToByte(hexString.Substring(x, 2), 16))
                                     .ToArray();

            // Convert the byte array to a BigInteger
            BigInteger bigInteger = new BigInteger(bytes.Reverse().ToArray());

            // Convert the BigInteger to a decimal string
            return bigInteger.ToString();
        }

    }
}
