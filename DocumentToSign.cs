using System.Collections.Generic;


namespace ProductVerificationTest.dotnet.Models
{


    public class XmlValidationDocument
    {
        public string Document { get; set; }
    }

    public class DocumentToVerify
    {
        public string Document { get; set; }
        public string SignedElement  { get; set; }
    }

    public class DocumentToSign 
    {
        public string Document { get; set; }
        public IList<ElementItem> Elements { get; set;}
        public string KeySerialNumber { get; set; }
    }

    public class ElementItem
    {
        public string Id { get; set; }
        public string Key { get; set; }
    }
}