using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;

namespace ProductVerificationTest.dotnet
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Starting tests");
            SignAndVerifyFilesInDirectory("./unsigned");
            VerifyFilesInDirectory("./signed");
            SendSignedMessages();
        }

        static void SignAndVerifyFilesInDirectory(string path){
            foreach (string file in Directory.EnumerateFiles(path,"*.xml" , SearchOption.AllDirectories))
        {
            // do something
            var xmlDoc = new System.Xml.XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.Load(file);

            var cert = Models.DocumentSigning.GetCertificates()
                .ToList()
                .First();

            var signature = Models.DocumentSigning.GetSignature(xmlDoc, cert,"#products" );
            Console.WriteLine(signature.OuterXml);

        }
              
        }

        static void VerifyFilesInDirectory(string path){

        }
        
        static void SendSignedMessages(){

        }

    }


}
