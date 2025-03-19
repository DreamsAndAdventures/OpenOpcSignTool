using System;
using System.IO;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Threading.Tasks;

namespace OpenVsixSignTool.Core
{
    internal class XmlSignatureBuilder
    {
        private readonly XmlDocument _document;
        private readonly ISigningContext _signingContext;
        private readonly XmlElement _signatureElement;
        private XmlElement _objectElement;


        /// <summary>
        /// Creates a new signature with the correct namespace and empty root <c>Signature</c> element.
        /// </summary>
        internal XmlSignatureBuilder(ISigningContext signingContext)
        {
            _signingContext = signingContext;
            _document = new XmlDocument();
            var manager = new XmlNamespaceManager(_document.NameTable);
            manager.AddNamespace("", OpcKnownUris.XmlDSig.AbsoluteUri);
            _signatureElement = CreateDSigElement("Signature");
        }

        private XmlElement CreateDSigElement(string name) => _document.CreateElement(name, OpcKnownUris.XmlDSig.AbsoluteUri);

        public XmlDocument Build()
        {
            if (_objectElement == null)
            {
                throw new InvalidOperationException("A manifest has not been set on the builder.");
            }
            XmlElement keyInfoElement, signedInfo, signatureValue, xadesObject;
            var info = new HashAlgorithmInfo(_signingContext.FileDigestAlgorithmName);
            using (var canonicalHashAlgorithm = info.Create())
            {
                // Insert Xades
                xadesObject = InsertXades();

                // This is not the object to use for the hash

                XmlElement signedProperties = null;

                XmlElement qualifying = xadesObject["QualifyingProperties"];
                if (qualifying != null)
                {
                    signedProperties = qualifying["SignedProperties"];
                }

                byte[] xadesElementHash = null;
                string canonicalizationMethodXadesId = string.Empty;

                if ( signedProperties != null)
                {
                    using (var xadesElementCanonicalData = CanonicalizeElement(signedProperties, out canonicalizationMethodXadesId))
                    {
                        xadesElementHash = canonicalHashAlgorithm.ComputeHash(xadesElementCanonicalData);
                    }
                }

                byte[] objectElementHash;
                string canonicalizationMethodObjectId;
                using (var objectElementCanonicalData = CanonicalizeElement(_objectElement, out canonicalizationMethodObjectId))
                {
                    objectElementHash = canonicalHashAlgorithm.ComputeHash(objectElementCanonicalData);
                }
                keyInfoElement = BuildKeyInfoElement();

                Stream signerInfoCanonicalStream;

                if ( signedProperties != null && 
                    xadesElementHash != null && 
                    canonicalizationMethodXadesId != string.Empty)
                {
                    (signerInfoCanonicalStream, signedInfo) = BuildSignedInfoElement([(
                    _objectElement,
                    objectElementHash,
                    info.XmlDSigIdentifier.AbsoluteUri,
                    canonicalizationMethodObjectId),
                    (
                    signedProperties,
                    xadesElementHash,
                    info.XmlDSigIdentifier.AbsoluteUri,
                    canonicalizationMethodXadesId)]);
                }
                else
                {
                    (signerInfoCanonicalStream, signedInfo) = BuildSignedInfoElement((
                        _objectElement,
                        objectElementHash,
                        info.XmlDSigIdentifier.AbsoluteUri,
                        canonicalizationMethodObjectId));
                }
                //(signerInfoCanonicalStream, signedInfo) = BuildSignedInfoElement((
                //    _objectElement,
                //    objectElementHash,
                //    info.XmlDSigIdentifier.AbsoluteUri,
                //    canonicalizationMethodObjectId));
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
            _signatureElement.AppendChild(xadesObject);
            _document.AppendChild(_signatureElement);
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

            foreach (var (element, digest, digestAlgorithm, method) in objects)
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
            signatureTimeValueElement.InnerText = _signingContext.ContextCreationTime.ToString("yyyy-MM-ddTHH:mm:ss.fzzz");

            signatureTimeElement.AppendChild(signatureTimeFormatElement);
            signatureTimeElement.AppendChild(signatureTimeValueElement);

            signaturePropertyElement.AppendChild(signatureTimeElement);
            signaturePropertiesElement.AppendChild(signaturePropertyElement);
            objectElement.AppendChild(signaturePropertiesElement);

            _objectElement = objectElement;
        }

        private XmlElement InsertXades()
        {
            XmlElement objectElement = null;

            XmlElement signedProperties = PreTimestampCall();

            byte[] response = null;
            Rfc3161TimestampToken token = TimestampCall(signedProperties, out response);

            if (token != null && response != null)
            {
                XmlElement canonicalizationMethod = CreateDSigElement("CanonicalizationMethod");
                XmlAttribute algorithm = _document.CreateAttribute("Algorithm");

                algorithm.Value = new XmlDsigC14NTransform(false).Algorithm; ;
                canonicalizationMethod.Attributes.Append(algorithm);

                XmlElement encapsulatedTimestamp = CreateDSigElement("EncapsulatedTimeStamp");
                XmlAttribute encoding = _document.CreateAttribute("Encoding");
                encoding.Value = "http://uri.etsi.org/01903/v1.2.2#DER";   // This is a guess
                encapsulatedTimestamp.Attributes.Append(algorithm);
                encapsulatedTimestamp.InnerText = Convert.ToBase64String(response);

                XmlElement signatureTimeStamp = CreateDSigElement("SignatureTimeStamp");
                signatureTimeStamp.AppendChild(canonicalizationMethod);
                signatureTimeStamp.AppendChild(encapsulatedTimestamp);

                XmlElement unsignedSignatureProperties = CreateDSigElement("UnsignedSignatureProperties");
                unsignedSignatureProperties.AppendChild(signatureTimeStamp);
                XmlElement unsignedProperties = CreateDSigElement("UnsignedProperties");
                unsignedProperties.AppendChild(unsignedSignatureProperties);

                XmlElement qualifyingProperties = CreateDSigElement("QualifyingProperties");
                XmlAttribute target = _document.CreateAttribute("Target");
                target.Value = "#Signature-" + Guid.NewGuid().ToString();
                qualifyingProperties.Attributes.Append(target);

                XmlAttribute xadesVersion = _document.CreateAttribute("xadesv141");
                xadesVersion.Value = "http://uri.etsi.org/01903/v1.4.1#";
                qualifyingProperties.Attributes.Append(xadesVersion);


                qualifyingProperties.AppendChild(signedProperties);
                qualifyingProperties.AppendChild(unsignedProperties);

                objectElement = CreateDSigElement("Object");
                objectElement.AppendChild(qualifyingProperties);
            }

            return objectElement;
        }

        private XmlElement PreTimestampCall()
        {
            byte[] certificateBytes = _signingContext.Certificate.Export(X509ContentType.Cert);
            byte[] certificateHashBytes = SHA256.Create().ComputeHash(certificateBytes);
            string encodedHash = Convert.ToBase64String(certificateHashBytes);

            // Now I can at least create the XAdES element.

            XmlElement digestMethod = CreateDSigElement("DigestMethod");
            XmlAttribute algorithm = _document.CreateAttribute("Algorithm");
            algorithm.Value = "http://www.w3.org/2001/04/xmlenc#sha256";
            digestMethod.Attributes.Append(algorithm);

            XmlElement digestValue = CreateDSigElement("DigestValue");
            digestValue.InnerText = encodedHash;

            XmlElement certDigest = CreateDSigElement("CertDigest");
            certDigest.AppendChild(digestMethod);
            certDigest.AppendChild(digestValue);

            XmlElement issuerNameElement = CreateDSigElement("X509IssuerName");
            issuerNameElement.InnerText = _signingContext.Certificate.IssuerName.Name;
            XmlElement issuerSerialNumber = CreateDSigElement("X509SerialNumber");
            issuerSerialNumber.InnerText = _signingContext.Certificate.SerialNumber;

            XmlElement issuerSerial = CreateDSigElement("IssuerSerial");
            issuerSerial.AppendChild(issuerNameElement);
            issuerSerial.AppendChild(issuerSerialNumber);

            XmlElement cert = CreateDSigElement("Cert");
            cert.AppendChild(certDigest);
            cert.AppendChild(issuerSerial);

            XmlElement signingCertificate = CreateDSigElement("SigningCertificate");
            signingCertificate.AppendChild(cert);

            XmlElement signingTime = CreateDSigElement("SigningTime");
            signingTime.InnerText = _signingContext.ContextCreationTime.ToString("yyyy-MM-ddTHH:mm:ss.fzzz");

            XmlElement signedSignatureProperties = CreateDSigElement("SignedSignatureProperties");
            signedSignatureProperties.AppendChild(signingTime);
            signedSignatureProperties.AppendChild(signingCertificate);

            XmlElement signedProperties = CreateDSigElement("SignedProperties");
            XmlAttribute signedPropertiesId = _document.CreateAttribute("Id");
            signedPropertiesId.Value = "SignedProperties-" + Guid.NewGuid().ToString();
            // terrible programming here
            _xadesInternalLink = "#" + signedPropertiesId.Value;
            signedProperties.Attributes.Append(signedPropertiesId);

            signedProperties.AppendChild(signedSignatureProperties);

            return signedProperties;
        }

        private string _xadesInternalLink = string.Empty;

        private Rfc3161TimestampToken TimestampCall(XmlElement signedProperties, out byte[] response)
        {
            Rfc3161TimestampToken token = null;
            response = null;

            HashAlgorithmInfo info = new HashAlgorithmInfo(_signingContext.FileDigestAlgorithmName);
            HashAlgorithm canonicalHashAlgorithm = info.Create();
            string canonicalizationMethodObjectId;
            Stream signedPropertiesCanonicalData = CanonicalizeElement(
                signedProperties,
                out canonicalizationMethodObjectId);
            byte[] signedPropertiesHash = canonicalHashAlgorithm.ComputeHash(signedPropertiesCanonicalData);

            Rfc3161TimestampRequest request = Rfc3161TimestampRequest.CreateFromHash(signedPropertiesHash,
                HashAlgorithmName.SHA256,
                nonce: null,
                requestSignerCertificates: true);

            request.GetNonce();

            byte[] responseBytes = TimestampCallAsync(request).Result;

            int bytesConsumed;

            if (responseBytes != null)
            {
                token = request.ProcessResponse(responseBytes, out bytesConsumed);
                response = responseBytes;
            }

            return token;
        }

        private async Task<byte[]> TimestampCallAsync(Rfc3161TimestampRequest request)
        {
            byte[] response = null;

            byte[] requestBytes = request.Encode();

            //string timestampServer = "http://timestamp.digicert.com";
            string timestampServer = "http://timestamp.entrust.net/rfc3161ts2";

            using (HttpClient client = new HttpClient())
            {
                HttpContent content = new ByteArrayContent(requestBytes);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");

                HttpResponseMessage httpResponse = await client.PostAsync(timestampServer, content);

                if (httpResponse.IsSuccessStatusCode)
                {
                    response = await httpResponse.Content.ReadAsByteArrayAsync();
                }
                else
                {
                    bool oops = true;
                }
            }

            return response;
        }

    }
}
