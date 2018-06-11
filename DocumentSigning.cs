using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Web;
using System.Xml;
using System.IO;


namespace ProductVerificationTest.dotnet.Models
{
    public class DocumentSigning
    {
        static IList<X509Certificate2> _certificates = new List<X509Certificate2>();

        internal static IList<X509Certificate2> GetCertificates()
        {
            var result = new List<X509Certificate2>();


            var certificateFileNames = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("\\certs\\test-private\\serialnumber.pfx", "Cl3@n3n3rgy")
            };

            if (_certificates.Count == certificateFileNames.Count) return _certificates;


            foreach (var cert in certificateFileNames)
            {
                byte[] rawData = Models.DocumentSigning.ReadFile(AppDomain.CurrentDomain.BaseDirectory + cert.Key);
                X509Certificate2 x509 = new X509Certificate2(rawData,cert.Value, X509KeyStorageFlags.MachineKeySet);

                var pk = x509.PrivateKey;
                if (pk == null) throw new Exception("Private key not found");
                result.Add(x509);

                System.Diagnostics.Debug.Print(x509.GetExpirationDateString());

            }

            _certificates = result;
            return result;

        }



        public static XmlElement GetSignature(XmlDocument document, X509Certificate2 cert, string elementToSignId)
        {

            SignedXml signedXml = new SignedXml(document)
            {
                SigningKey = cert.PrivateKey
            };
            signedXml.SigningKey = cert.PrivateKey;

            // Create a reference to be signed.
            Reference reference = new Reference()
            {
                Uri = elementToSignId
            };


            // Add an enveloped transformation to the reference.            
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform(true);
            reference.AddTransform(env);

            //canonicalize
            XmlDsigC14NTransform c14t = new XmlDsigC14NTransform();
            reference.AddTransform(c14t);


            //Key Info

            KeyInfoName kin = new KeyInfoName()
            {
                Value = cert.Subject
            };

            //RSA Key Provider
            // RSACryptoServiceProvider rsaprovider = (RSACryptoServiceProvider)cert.PublicKey.Key;
            // RSAKeyValue rkv = new RSAKeyValue(rsaprovider);


            //System.Security.Cryptography..X509IssuerSerial xserial;
            //xserial.IssuerName = cert.IssuerName.Name;
            //xserial.SerialNumber = cert.SerialNumber;

            KeyInfo keyInfo = new KeyInfo();
            KeyInfoX509Data keyInfoData = new KeyInfoX509Data(cert);
            //keyInfo.AddClause(new KeyInfoX509Data(cert));
            keyInfoData.AddIssuerSerial(cert.IssuerName.Name, cert.SerialNumber);
            keyInfo.AddClause(keyInfoData);
            

            keyInfo.AddClause(kin);
            //keyInfo.AddClause(rkv);
            // Add the KeyInfo object to the SignedXml object.
            keyInfo.AddClause(new RSAKeyValue((RSA)cert.PrivateKey));
            signedXml.KeyInfo = keyInfo;

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();


            return xmlDigitalSignature;
        }

        internal static byte[] ReadFile(string fileName)
        {
            FileStream f = new FileStream(fileName, FileMode.Open, FileAccess.Read);
            int size = (int)f.Length;
            byte[] data = new byte[size];
            size = f.Read(data, 0, size);
            f.Close();
            return data;
        }

        public static bool CheckXmlSignatureX509(XmlDocument Document, string signatureElementName)
        {
            SignedXml signedXml = GetSignatureElement(Document, signatureElementName);
            //X509Certificate2 cert = signedXml.KeyInfo[0]

            var a = signedXml.KeyInfo;
            X509Certificate2 cert = null;
            KeyInfoX509Data keyinfo = null;

            foreach (var b in a)
            {
                if (b is KeyInfoX509Data)
                {
                    keyinfo = (KeyInfoX509Data)b;
                    break;
                }
            }
            cert = (X509Certificate2)keyinfo.Certificates[0];



            // Return if the signature checks out against the supplied cert
            if (!signedXml.CheckSignature(cert.PublicKey.Key))
                return false;

            return signedXml.CheckSignature(cert, true);
        }

        private static SignedXml GetSignatureElement(XmlDocument Document, string signatureElementName)
        {
            // Look for the signature element in the XML
            //XmlNodeList nodeList = Document.GetElementsByTagName("Signature");
            XmlNodeList nodeList = Document.GetElementsByTagName("Signature");


            // Throw an exception if no signature was found.
            if (nodeList.Count <= 0)
            {
                throw new CryptographicException("Verification failed: No Signature was found in the document.");
            }

            XmlNode signaturNode = null;

            foreach (XmlNode node in nodeList)
            {
                foreach (XmlNode childnode in node)
                {
                    if (childnode.Name == "SignedInfo")
                    {
                        foreach (XmlNode refNode in childnode)
                        {
                            if (refNode.Name == "Reference" && refNode.Attributes[0].Name == "URI")
                            {
                                if (refNode.Attributes[0].Value == "#" + signatureElementName)
                                {
                                    signaturNode = node;
                                    break;
                                }
                            }
                        }
                        break;
                    }
                }

            }

            if (signaturNode == null) throw new Exception("error finding referrence element.");
            //if (signaturNode is null) throw new Exception("Signature Referrence not found.");

            SignedXml signedXml = new SignedXml(Document);

            // Load the first <signature> node.    return signaturNode;
            signedXml.LoadXml((XmlElement)signaturNode);
            return signedXml;
        }
    }
}