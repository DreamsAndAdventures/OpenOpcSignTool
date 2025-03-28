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

namespace OpenVsixSignTool.Core
{
    internal class XmlSignatureBuilder
    {
        private readonly XmlDocument _document;
        private readonly ISigningContext _signingContext;
        private readonly XmlElement _signatureElement;
        private XmlElement _objectElement;

        private const string XadesNamespace = "http://uri.etsi.org/01903/v1.3.2#";
        private const string XadesSignedProperties = "http://uri.etsi.org/01903#SignedProperties";



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
        private XmlElement CreateXadesDSigElement(string name) => CreateDSigElement(name);
            //_document.CreateElement("ds", name, null);

        private XmlElement CreateXadesElement(string name) => _document.CreateElement("xades", name, OpcKnownUris.XadesNamespace.AbsoluteUri);

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
                byte[] objectElementHash;
                string canonicalizationMethodObjectId;
                using (var objectElementCanonicalData = CanonicalizeElement(_objectElement, out canonicalizationMethodObjectId))
                {
                    objectElementHash = canonicalHashAlgorithm.ComputeHash(objectElementCanonicalData);
                }
                keyInfoElement = BuildKeyInfoElement();

                // Insert Xades
                xadesObject = CreateXades();


                // This is not the object to use for the hash

                XmlElement signedProperties = null;

                XmlElement qualifying = xadesObject["xades:QualifyingProperties"];
                if (qualifying != null)
                {
                    signedProperties = qualifying["xades:SignedProperties"];
                }

                string signedPropertiesId = signedProperties.Attributes["Id"].Value;


                SignedXml signedXml = new SignedXml();
                signedXml.SigningKey = _signingContext.Certificate.GetRSAPrivateKey();
                signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
                signedXml.Signature.Id = "Signature-" + Guid.NewGuid().ToString();

                DataObject dataObject = new DataObject();
                dataObject.LoadXml(xadesObject);

                signedXml.AddObject(dataObject);

                Reference myRef = new Reference()
                {
                    Uri = "#" + signedPropertiesId,
                    Type = "http://uri.etsi.org/01903#SignedProperties",
                    DigestMethod = SignedXml.XmlDsigSHA256Url
                };

                signedXml.AddReference(myRef);
                signedXml.ComputeSignature();


                XmlDocument signedPropertiesDoc = new XmlDocument();
                XmlDocument signedWithTable = new XmlDocument(_document.NameTable);
                signedPropertiesDoc.LoadXml(signedProperties.OuterXml);
                signedWithTable.LoadXml(signedProperties.OuterXml);

                string original = signedProperties.OuterXml;
                string without = signedPropertiesDoc.OuterXml;
                string with = signedWithTable.OuterXml; 

                XmlDsigC14NTransform transformOne = new XmlDsigC14NTransform();
                XmlDsigC14NTransform transformTwo = new XmlDsigC14NTransform();
                transformOne.LoadInput(signedPropertiesDoc);
                transformTwo.LoadInput(signedWithTable);

                Stream canonicalStream = (Stream)transformOne.GetOutput(typeof(Stream));
                Stream canonicalStreamTwo = (Stream)transformTwo.GetOutput(typeof(Stream));

                byte[] canonicalBytes = new byte[canonicalStream.Length];
                canonicalStream.Read(canonicalBytes, 0, canonicalBytes.Length);

                byte[] canonicalBytesTwo = new byte[canonicalStreamTwo.Length];
                canonicalStreamTwo.Read(canonicalBytesTwo, 0, canonicalBytesTwo.Length);

                byte[] MyHash = canonicalHashAlgorithm.ComputeHash(canonicalBytes);
                byte[] MyHashTwo = canonicalHashAlgorithm.ComputeHash(canonicalStreamTwo);

                byte[] useHash = MyHashTwo;

                string encoded = Convert.ToBase64String(MyHash);
                string encodedTwo = Convert.ToBase64String(MyHashTwo);


                Stream signerInfoCanonicalStream;

                if ( signedProperties != null &&
                    MyHash != null )
                {
                    (signerInfoCanonicalStream, signedInfo) = BuildSignedInfoElement([(
                    _objectElement,
                    objectElementHash,
                    info.XmlDSigIdentifier.AbsoluteUri,
                    canonicalizationMethodObjectId),
                    (
                    signedProperties,
                    useHash,
                    info.XmlDSigIdentifier.AbsoluteUri,
                    canonicalizationMethodObjectId)]);
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

                ProcessXades(xadesObject, useHash);
            }

            _signatureElement.AppendChild(signedInfo);
            _signatureElement.AppendChild(signatureValue);
            _signatureElement.AppendChild(keyInfoElement);
            _signatureElement.AppendChild(_objectElement);
            _signatureElement.AppendChild(xadesObject);
            return _document;
        }

        private XmlElement BuildSignatureValue(byte[] signerInfoElementHash)
        {
            var signatureValueElement = CreateDSigElement("SignatureValue");
            signatureValueElement.InnerText = Convert.ToBase64String(_signingContext.SignDigest(signerInfoElementHash));
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

        private XmlElement CreateXades()
        {
            byte[] properQuestion = _signingContext.Certificate.GetCertHash();
            byte[] certificateBytes = _signingContext.Certificate.Export(X509ContentType.Cert);
            byte[] certificateHashBytes = SHA256.Create().ComputeHash(certificateBytes);
            string encodedHash = Convert.ToBase64String(properQuestion);

            // Now I can at least create the XAdES element.

            XmlElement digestMethod = CreateXadesDSigElement("DigestMethod");
            XmlAttribute algorithm = _document.CreateAttribute("Algorithm");
            algorithm.Value = "http://www.w3.org/2001/04/xmlenc#sha256";
            digestMethod.Attributes.Append(algorithm);

            XmlElement digestValue = CreateXadesDSigElement("DigestValue");
            digestValue.InnerText = encodedHash;

            XmlElement certDigest = CreateXadesElement("CertDigest");
            certDigest.AppendChild(digestMethod);
            certDigest.AppendChild(digestValue);

            XmlElement issuerNameElement = CreateXadesDSigElement("X509IssuerName");
            issuerNameElement.InnerText = _signingContext.Certificate.IssuerName.Name;
            XmlElement issuerSerialNumber = CreateXadesDSigElement("X509SerialNumber");
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
            signingTime.InnerText = _signingContext.ContextCreationTime.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

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



            XmlElement objectElement = CreateDSigElement("Object");
            objectElement.AppendChild(qualifyingProperties);








            return objectElement;
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
