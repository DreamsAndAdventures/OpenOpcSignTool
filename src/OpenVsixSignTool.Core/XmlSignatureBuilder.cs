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
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Reflection;

namespace OpenVsixSignTool.Core
{
    internal class XmlSignatureBuilder
    {
        private readonly XmlDocument _document = null;
        private readonly ISigningContext _signingContext = null;
        private readonly XmlElement _signatureElement = null;
        private XmlElement _objectElement = null;
        private XmlElement _xadesElement = null;

        /// <summary>
        /// Creates a new signature with the correct namespace and empty root <c>Signature</c> element.
        /// </summary>
        internal XmlSignatureBuilder(ISigningContext signingContext)
        {
            _signingContext = signingContext;
            _document = new XmlDocument();
            var manager = new XmlNamespaceManager(_document.NameTable);
            manager.AddNamespace("ds", OpcKnownUris.XmlDSig.AbsoluteUri);
            manager.AddNamespace("xades", OpcKnownUris.XadesNamespace.AbsoluteUri);
            _signatureElement = CreateDSigElement("Signature");
            _document.AppendChild(_signatureElement);
        }

        private XmlElement CreateDSigElement(string name) => _document.CreateElement("ds", name, OpcKnownUris.XmlDSig.AbsoluteUri);

        private XmlElement CreateXadesElement(string name) => _document.CreateElement("xades", name, OpcKnownUris.XadesNamespace.AbsoluteUri);

        public XmlDocument BuildAll()
        {
            bool addXades = false;
            if (_objectElement == null)
            {
                throw new InvalidOperationException("A manifest has not been set on the builder.");
            }
            if (_xadesElement == null)
            {
                throw new InvalidOperationException("Xades Timestamp has not been set on the builder.");
            }

            XmlDocument workingDoc = new XmlDocument(_document.NameTable);
            XmlNode cloned = _signatureElement.Clone();
            cloned.AppendChild(_objectElement.Clone());
            if (addXades)
            {
                cloned.AppendChild(_xadesElement.Clone());
            }
            workingDoc.LoadXml(cloned.OuterXml);

            HashAlgorithmInfo hashAlgorithmInfo = new HashAlgorithmInfo(_signingContext.FileDigestAlgorithmName);
            HashAlgorithm hashAlgorithm = hashAlgorithmInfo.Create();

            SignedXml signedXml = InitializeSignedXml(workingDoc, hashAlgorithmInfo, addXades);

            try
            {
                // SignedInfo Element
                signedXml.ComputeSignature();
                return null;
            }
            catch (Exception ex)
            {
                XmlElement rebuildSignedInfo;
                Stream signedInfoStream = BuildSignedInfoElement(signedXml, out rebuildSignedInfo);
                
                byte[] signerInfoElementHash = hashAlgorithm.ComputeHash(signedInfoStream);
                XmlElement rebuildSignatureValue = BuildSignatureValue(signerInfoElementHash);
                
                XmlElement keyInfoElement = BuildKeyInfoElement();

                _signatureElement.AppendChild(rebuildSignedInfo);
                _signatureElement.AppendChild(keyInfoElement);
                _signatureElement.AppendChild(rebuildSignatureValue);
                _signatureElement.AppendChild(_objectElement);
                if (addXades)
                {
                    _signatureElement.AppendChild(_xadesElement);
                    //ProcessXades(_xadesElement, GetXadesDigest(signedXml));
                }
            }

            return _document;
        }

        public SignedXml InitializeSignedXml(XmlDocument document, HashAlgorithmInfo hashAlgorithmInfo, bool addXades)
        {
            SignedXml signedXml = new SignedXml(document);

            RSA ensureExceptionIsThrown = null;
            signedXml.SigningKey = ensureExceptionIsThrown;
            //signedXml.SigningKey = _signingContext.Certificate.GetRSAPrivateKey();
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

        public byte[] GetXadesDigest( SignedXml signedXml )
        {
            byte[] digest = null;

            foreach( Reference reference in signedXml.SignedInfo.References)
            {
                if (reference.Type == OpcKnownUris.XadesSignedProperties.AbsoluteUri)
                {
                    digest = reference.DigestValue;
                    break;
                }
            }

            return digest;
        }

        public byte[] GetDocumentDigest(SignedXml signedXml, HashAlgorithm hashAlgorithm)
        {
            MethodInfo getC14NDigestMethod = typeof(SignedXml).GetMethod(
                "GetC14NDigest", BindingFlags.NonPublic | BindingFlags.Instance);

            if (getC14NDigestMethod == null)
            {
                throw new InvalidOperationException("GetC14NDigest method not found.");
            }

            // Invoke the GetC14NDigest method
            byte[] c14nDigest = (byte[])getC14NDigestMethod.Invoke(signedXml,
                new object[] { hashAlgorithm });

            return c14nDigest;
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
            _document.AppendChild(_signatureElement);
            return _document;
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

        private XmlElement BuildSignatureValue(byte[] signerInfoElementHash)
        {
            var signatureValueElement = CreateDSigElement("SignatureValue");
            signatureValueElement.InnerText = Convert.ToBase64String(
                _signingContext.SignDigest(signerInfoElementHash));
            return signatureValueElement;
        }

        int counter = 0;

        private Stream CanonicalizeElement(XmlElement element, out string canonicalizationMethodUri, Action<string> setCanonicalization = null)
        {
            //The canonicalization transformer can't reasonable do just an element. It
            //seems content to do an entire XmlDocument.
            var transformer = new XmlDsigC14NTransform(false);
            setCanonicalization?.Invoke(transformer.Algorithm);

            var newDocument = new XmlDocument(_document.NameTable);
            newDocument.LoadXml(element.OuterXml);

            newDocument.Save(counter.ToString() + "_Save.xml");
            counter++;

            transformer.LoadInput(newDocument);

            var result = transformer.GetOutput(typeof(Stream));
            canonicalizationMethodUri = transformer.Algorithm;
            if (result is Stream s)
            {
                return s;
            }
            throw new NotSupportedException("Unable to canonicalize element.");
        }

        private Stream BuildSignedInfoElement(SignedXml signedXml, out XmlElement signedInfoElement)
        {
            signedInfoElement = CreateDSigElement("SignedInfo");
            XmlElement canonicalizationMethodElement = CreateDSigElement("CanonicalizationMethod");
            XmlAttribute canonicalizationMethodAlgorithmAttribute = _document.CreateAttribute("Algorithm");            
            canonicalizationMethodElement.Attributes.Append(canonicalizationMethodAlgorithmAttribute);

            XmlElement signatureMethodElement = CreateDSigElement("SignatureMethod");
            XmlAttribute signatureMethodAlgorithmAttribute = _document.CreateAttribute("Algorithm");
            signatureMethodAlgorithmAttribute.Value = _signingContext.XmlDSigIdentifier.AbsoluteUri;
            signatureMethodElement.Attributes.Append(signatureMethodAlgorithmAttribute);

            signedInfoElement.AppendChild(canonicalizationMethodElement);
            signedInfoElement.AppendChild(signatureMethodElement);

            foreach (Reference reference in signedXml.SignedInfo.References)
            {
                XmlElement referenceElement = CreateDSigElement("Reference");

                XmlAttribute referenceUriAttribute = _document.CreateAttribute("URI");
                referenceUriAttribute.Value = reference.Uri;
                referenceElement.Attributes.Append(referenceUriAttribute);

                XmlAttribute referenceTypeAttribute = _document.CreateAttribute("Type");
                referenceTypeAttribute.Value = reference.Type;
                referenceElement.Attributes.Append(referenceTypeAttribute);

                XmlElement digestMethodElement = CreateDSigElement("DigestMethod");
                XmlAttribute digestMethodAlgorithmAttribute = _document.CreateAttribute("Algorithm");
                digestMethodAlgorithmAttribute.Value = reference.DigestMethod;
                digestMethodElement.Attributes.Append(digestMethodAlgorithmAttribute);
                referenceElement.AppendChild(digestMethodElement);

                XmlElement digestValueElement = CreateDSigElement("DigestValue");
                digestValueElement.InnerText = Convert.ToBase64String(reference.DigestValue);
                referenceElement.AppendChild(digestValueElement);

                signedInfoElement.AppendChild(referenceElement);
            }

            return CanonicalizeElement(signedInfoElement, 
                out _, 
                c => canonicalizationMethodAlgorithmAttribute.Value = c);
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
                if (element.Prefix == "xades")
                {
                    referenceTypeAttribute.Value = OpcKnownUris.XadesSignedProperties.AbsoluteUri;
                }
                else
                {
                    referenceTypeAttribute.Value = OpcKnownUris.XmlDSigObject.AbsoluteUri;
                }

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



        private void ProcessXades(XmlElement xadesElement, byte[] hash)
        {
            byte[] response = null;
            Rfc3161TimestampToken token = TimestampCall(hash, out response);

            if (token != null && response != null)
            {
                XmlElement canonicalizationMethod = CreateDSigElement("CanonicalizationMethod");
                XmlAttribute algorithm = _document.CreateAttribute("Algorithm");

                algorithm.Value = new XmlDsigC14NTransform(false).Algorithm;
                canonicalizationMethod.Attributes.Append(algorithm);

                XmlElement encapsulatedTimestamp = CreateXadesElement("EncapsulatedTimeStamp");
                XmlAttribute encoding = _document.CreateAttribute("Encoding");
                encoding.Value = "http://uri.etsi.org/01903/v1.2.2#DER";   // This is a guess
                encapsulatedTimestamp.Attributes.Append(encoding);
                encapsulatedTimestamp.InnerText = Convert.ToBase64String(response);

                XmlElement signatureTimeStamp = CreateXadesElement("SignatureTimeStamp");
                signatureTimeStamp.AppendChild(canonicalizationMethod);
                signatureTimeStamp.AppendChild(encapsulatedTimestamp);

                XmlElement unsignedSignatureProperties = CreateXadesElement("UnsignedSignatureProperties");
                unsignedSignatureProperties.AppendChild(signatureTimeStamp);
                XmlElement unsignedProperties = CreateXadesElement("UnsignedProperties");
                unsignedProperties.AppendChild(unsignedSignatureProperties);

                XmlElement qualifyingProperties = xadesElement["xades:QualifyingProperties"];

                qualifyingProperties.AppendChild(unsignedProperties);
            }
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

        private Rfc3161TimestampToken TimestampCall(byte[] xadesHash,
            out byte[] response)
        {
            Rfc3161TimestampToken token = null;
            response = null;

            Rfc3161TimestampRequest request = Rfc3161TimestampRequest.CreateFromHash(
                xadesHash,
                _signingContext.FileDigestAlgorithmName,
                nonce: null,
                requestSignerCertificates: true);

            request.GetNonce();

            byte[] responseBytes = TimestampCallAsync(request).Result;

            int bytesConsumed;

            if (responseBytes != null)
            {
                token = request.ProcessResponse(responseBytes, out bytesConsumed);
                response = responseBytes;

                string tryMe = Convert.ToBase64String(response);
                byte[] backAgain = Convert.FromBase64String(tryMe);

                Rfc3161TimestampTokenInfo localtoken = token.TokenInfo;
                X509ExtensionCollection coll = localtoken.GetExtensions();
                SignedCms cms = token.AsSignedCms();
                bool wait = true;


                if (Rfc3161TimestampToken.TryDecode(response,
                    out Rfc3161TimestampToken timestampResponse,
                    out int consumed))
                {
                    Rfc3161TimestampTokenInfo token2 = timestampResponse.TokenInfo;
                    X509ExtensionCollection coll3 = token2.GetExtensions();
                    SignedCms cms3 = timestampResponse.AsSignedCms();

                    bool keepGoing = true;
                }
                else
                {
                    bool aShit = true;
                }
            }

            return token;
        }

        private async Task<byte[]> TimestampCallAsync(Rfc3161TimestampRequest request)
        {
            byte[] response = null;

            byte[] requestBytes = request.Encode();

            string timestampServer = "http://timestamp.digicert.com";
            //string timestampServer = "http://timestamp.entrust.net/rfc3161ts2";

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
