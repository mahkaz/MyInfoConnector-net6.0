using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace sg.gov.ndi.MyInfoConnector
{
    public class MyInfoSecurityHelper
    {
        static RandomGenerator _randomGenerator = new RandomGenerator();

        /// <summary>
        /// Used for nonce. Cryptographically random
        /// </summary>
        public static int GetRandomInteger()
        {
            var randomValue = _randomGenerator.Next(0, int.MaxValue);
            return randomValue;
        }

        public static string GenerateAuthorizationHeader(string defaultHeader, string bearer)
        {
            string authHeader;

            if (bearer != null)
            {
                authHeader = ApplicationConstant.PKI_SIGN + " " + defaultHeader + "," + bearer;
            }
            else
            {
                authHeader = ApplicationConstant.PKI_SIGN + " " + defaultHeader;
            }

            return authHeader;
        }

        public static string GenerateBaseString(string method, string url, string baseParams)
        {
            string basestring = method.ToUpper() + "&" + url + "&" + baseParams;
            return basestring;
        }

        public static string GenerateSignature(string input, string privateKeyXml)
        {
            string hashSignatureBase64;

            var rsaProvider = new RSACryptoServiceProvider();
            rsaProvider.FromXmlString(privateKeyXml);
            var rsaFormatter = new RSAPKCS1SignatureFormatter(rsaProvider);
            rsaFormatter.SetHashAlgorithm("SHA256");
            var sha256 = SHA256.Create();
            var hashSignatureBytes = rsaFormatter.CreateSignature(sha256.ComputeHash(Encoding.UTF8.GetBytes(input)));
            hashSignatureBase64 = Convert.ToBase64String(hashSignatureBytes);

            return hashSignatureBase64;
        }

        public static object DecodeToken(string token)
        {
            string encodedPayload = token.Split('.')[1];
            string decodedPayload = Encoding.ASCII.GetString(FromBase64Url(encodedPayload));
            object jsonObject = JsonConvert.DeserializeObject(decodedPayload);
            return jsonObject;
        }


        public static bool VerifyToken(string token, AsymmetricAlgorithm rsaService)
        {
            bool signVerified = false;
            string[] tokenParts = token.TrimStart('"').TrimEnd('"').Split('.');

            var sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(tokenParts[0] + '.' + tokenParts[1]));

            var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsaService);
            rsaDeformatter.SetHashAlgorithm("SHA256");
            var signature = FromBase64Url(tokenParts[2]);

            if (rsaDeformatter.VerifySignature(hash, signature))
            {
                signVerified = true;
            }

            return signVerified;
        }

        private static byte[] FromBase64Url(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0
                ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/")
                                  .Replace("-", "+");
            return Convert.FromBase64String(base64);
        }

    }
}
