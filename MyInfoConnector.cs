using Newtonsoft.Json;
using System;
using Newtonsoft.Json.Linq;
using System.Net.Http;
using System.Configuration;
using System.Net.Http.Headers;

namespace sg.gov.ndi.MyInfoConnector
{

    public class MyInfoConnector : IMyInfoConnector
    {
        static readonly HttpClient Client = new HttpClient();
        private MyInfoConnectorConfig _config;

        /// <summary>
        /// Generate a URL for step 1
        /// </summary>
        /// <remarks>
        /// https://api.singpass.gov.sg/library/myinfo/developers/overview
        /// </remarks>
        public string GetAuthoriseUrl(string redirectUri, string state = null)
        {
            var authApiUrl = _config.AuthoriseUrl;
            var purpose = _config.Purpose;

            var args = $"?client_id={_config.ClientId}&attributes={_config.AttributeCsv}&purpose={Uri.EscapeDataString(purpose)}&redirect_uri={Uri.EscapeDataString(redirectUri)}";

            args += "&state=" + (string.IsNullOrEmpty(state) ? "no-state" : Uri.EscapeDataString(state));

            var authorizeUrl = authApiUrl + args;
            return authorizeUrl;
        }
        /// <summary>
        /// Backchannel authorise url if id-token was previously acquired during login
        /// </summary>
        /// <remarks>
        /// WARNING: backchannel authorisation is unavailable - this code is built on assumptions based on /authorise api
        /// </remarks>
        /// <param name="redirectUri"></param>
        /// <param name="state"></param>
        /// <param name="bc_session"></param>
        /// <returns></returns>
        public string GetBCAuthoriseUrl(string redirectUri, string state, string bc_session)
        {
            var authApiUrl = _config.AuthoriseUrl;
            var purpose = _config.Purpose;

            var args = $"?client_id={_config.ClientId}&attributes={_config.AttributeCsv}&purpose={Uri.EscapeDataString(purpose)}&redirect_uri={Uri.EscapeDataString(redirectUri)}&bc_session={bc_session}";

            args += "&state=" + (string.IsNullOrEmpty(state) ? "no-state" : Uri.EscapeDataString(state));

            var authorizeUrl = authApiUrl + args;
            return authorizeUrl;
        }

        public static MyInfoConnector Create(string path)
        {
            var map = new ExeConfigurationFileMap() { ExeConfigFilename = path };
            var libConfig = ConfigurationManager.OpenMappedExeConfiguration(map, ConfigurationUserLevel.None);
            var section = (libConfig.GetSection("appSettings") as AppSettingsSection);
            var config = MyInfoConnectorConfig.Load(section);

            return Create(config);
        }

        public static MyInfoConnector Create(MyInfoConnectorConfig config)
        {
            return new MyInfoConnector(config);
        }

        private MyInfoConnector(MyInfoConnectorConfig config)
        {
            _config = config;
        }

        /// <summary>
        /// Useful at app startup to confirm we can read certificates
        /// </summary>
        public (bool isValid, string[] messages) CheckConfiguration() => _config.IsValid();

        public string[] GetDiagnosticInfo() => _config.GetDiagnosticInfo();

        /// <summary>
        /// Invokes the getAccessToken API to generate the access token.
        /// The access token is then uses to invoke the person API to get the Person data.
        /// </summary>
        public string GetPersonJson(
            string redirectUri,
            string authCode,
            string state = null,
            string transactionId = null
            )
        {
            string result;
            string jsonResponse = null;

            string token = GetAccessToken(redirectUri, authCode, state);

            if (string.IsNullOrEmpty(token))
            {
                // Not authorised or something - either way cannot continue
                return null;
            }

            var jObject = JObject.Parse(MyInfoSecurityHelper.DecodeToken(token).ToString());
            string uinfin = (string)jObject.SelectToken("sub");

            // GET PERSON
            result = GetPersonJsonWorker(uinfin, "Bearer " + token, transactionId);

            if (_config.Environment == ApplicationConstant.SANDBOX)
            {
                jsonResponse = result;
            }
            else
            {
                try
                {
                    jsonResponse = DecodeTokenToPerson(result);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"{nameof(GetPersonJson)} failed to decode the encrypted result: {ex.Message}");
                }
            }

            return jsonResponse;
        }



        /// <summary>
        /// This API is invoked by your application server to obtain an "access
        /// token", which can be used to call the Person API for the actual data.
        /// Your application needs to provide a valid "authorisation code" from the
        /// authorise API in exchange for the "access token".
        /// </summary>
        protected string GetAccessToken(string redirectUri, string authCode, string state)
        {
            string baseParams;
            string accessToken;
            string baseString = string.Empty;
            string authHeader = string.Empty;
            

            try
            {
                var nonce = MyInfoSecurityHelper.GetRandomInteger();
                long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                string signature = null;

                // A) Forming the Signature Base String
                baseParams = $"{ApplicationConstant.APP_ID}={_config.ClientId}&{ApplicationConstant.CLIENT_ID}={_config.ClientId}&{ApplicationConstant.CLIENT_SECRET}={_config.ClientSecret}&{ApplicationConstant.CODE}={authCode}&{ApplicationConstant.GRANT_TYPE}={ApplicationConstant.AUTHORIZATION_CODE}&{ApplicationConstant.NONCE}={nonce}&{ApplicationConstant.REDIRECT_URI}={redirectUri}&{ApplicationConstant.SIGNATURE_METHOD}={ApplicationConstant.RS256}&{ApplicationConstant.STATE}={state}&{ApplicationConstant.TIMESTAMP}={timestamp}";
                baseString = MyInfoSecurityHelper.GenerateBaseString(ApplicationConstant.POST_METHOD, _config.TokenUrl, baseParams);

                if (!_config.IsSandbox)
                {
                    // B) Signing Base String to get Digital Signature
                    if (baseString != null)
                    {
                        signature = MyInfoSecurityHelper.GenerateSignature(baseString, _config.GetPrivateKey().ToXmlString(true));
                    }

                    // C) Assembling the Header
                    if (signature != null)
                    {
                        string headers = $"{ApplicationConstant.APP_ID}=\"{_config.ClientId}\",{ApplicationConstant.NONCE}=\"{nonce}\",{ApplicationConstant.SIGNATURE_METHOD}=\"{ApplicationConstant.RS256}\",{ApplicationConstant.SIGNATURE}=\"{signature}\",{ApplicationConstant.TIMESTAMP}=\"{timestamp}\"";
                        authHeader = MyInfoSecurityHelper.GenerateAuthorizationHeader(headers, null);
                    }
                }

                // D) Assembling the params
                string parameters = $"{ApplicationConstant.GRANT_TYPE}={ApplicationConstant.AUTHORIZATION_CODE}&{ApplicationConstant.CODE}={authCode}&{ApplicationConstant.REDIRECT_URI}={redirectUri}&{ApplicationConstant.CLIENT_ID}={_config.ClientId}&{ApplicationConstant.CLIENT_SECRET}={_config.ClientSecret}&{ApplicationConstant.STATE}={state}";

                // E) Prepare request for TOKEN API
                HttpResponseMessage httpResponse;
                using (HttpClient client = new HttpClient())
                {
                    // build content
                    var content = new StringContent(parameters.ToString());
                    content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");
                    content.Headers.ContentType.CharSet = "UTF-8";

                    // build request
                    var req = new HttpRequestMessage(HttpMethod.Post, new Uri(_config.TokenUrl));
                    req.Headers.Add(ApplicationConstant.CACHE_CONTROL, ApplicationConstant.NO_CACHE);
                    req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                    req.Content = content;
                    if (!_config.IsSandbox && !string.IsNullOrEmpty(authHeader))
                    {
                        req.Headers.Add(ApplicationConstant.AUTHORIZATION, authHeader);
                    }

                    // send
                    httpResponse = client.SendAsync(req).Result;

                }
                if (httpResponse.IsSuccessStatusCode)
                {
                    string result = httpResponse.Content.ReadAsStringAsync().Result;
                    object jsonObject = JsonConvert.DeserializeObject(result);
                    var jsonObj = JObject.Parse(jsonObject.ToString());
                    accessToken = (string)jsonObj.SelectToken("access_token");
                }
                else
                {
                    throw new Exception($"api call to {_config.TokenUrl} unsuccessful. (StatusCode {httpResponse.StatusCode})");
                }
            }
            catch (Exception ex)
            {
                var sgLocal = DateTimeOffset.UtcNow.ToOffset(TimeSpan.FromHours(8));
                throw new Exception($@"Request for AccessToken rejected. Support template data:
Time='{sgLocal}'
GET='{_config.TokenUrl}'
BaseString='{baseString}'
AuthHeader='{authHeader}'
AuthCode='{authCode}'
State='{state}'"
                , ex);
            }

            return accessToken;
        }

        /// <summary>
        /// Calls the Person API and returns a JSON response with the personal data that was requested. 
        /// Your application needs to provide a valid "access token" in exchange for the JSON data. 
        /// Once your application receives this JSON data, you can use this data to populate the online form on your application.
        /// </summary>
        protected string GetPersonJsonWorker(string uinFin, string bearer, string txnNo)
        {
            string baseParams;
            string content = string.Empty;

            // try
            // {
            var specificPersonUrl = $"{_config.PersonUrl}/{uinFin}/";

            var nonce = MyInfoSecurityHelper.GetRandomInteger();
            long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            string signature = null;
            string authHeader = null;

            // A) Forming the Signature Base String
            baseParams = $"{ApplicationConstant.APP_ID}={_config.ClientId}&{ApplicationConstant.ATTRIBUTE}={_config.AttributeCsv}&{ApplicationConstant.CLIENT_ID}={_config.ClientId}&{ApplicationConstant.NONCE}={nonce}&{ApplicationConstant.SIGNATURE_METHOD}={ApplicationConstant.RS256}&{ApplicationConstant.TIMESTAMP}={timestamp}";

            if (txnNo != null)
            {
                baseParams = $"{baseParams}&{ApplicationConstant.TRANSACTION_NO}={txnNo}";
            }
            string baseString = MyInfoSecurityHelper.GenerateBaseString(ApplicationConstant.GET_METHOD, specificPersonUrl, baseParams);

            // B) Signing Base String to get Digital Signature
            if (baseString != null)
            {
                var privateKey = _config.GetPrivateKey().ToXmlString(true);
                signature = MyInfoSecurityHelper.GenerateSignature(baseString, privateKey);
            }

            // C) Assembling the Header
            if (signature != null)
            {
                string header = $"{ApplicationConstant.APP_ID}=\"{_config.ClientId}\",{ApplicationConstant.NONCE}=\"{nonce}\",{ApplicationConstant.SIGNATURE_METHOD}=\"{ApplicationConstant.RS256}\",{ApplicationConstant.SIGNATURE}=\"{signature}\",{ApplicationConstant.TIMESTAMP}=\"{timestamp}\"";
                authHeader = MyInfoSecurityHelper.GenerateAuthorizationHeader(header, bearer);
            }

            // D) Assembling the params
            specificPersonUrl = $"{specificPersonUrl}?{ApplicationConstant.CLIENT_ID}={_config.ClientId}&{ApplicationConstant.ATTRIBUTE}={_config.AttributeCsv}";

            if (txnNo != null)
            {
                specificPersonUrl = $"{specificPersonUrl}&{ApplicationConstant.TRANSACTION_NO}={txnNo}";
            }

            // E) send request to get person json
            HttpResponseMessage httpResponse;
            using (HttpClient client = new HttpClient())
            {
                // build request
                var req = new HttpRequestMessage(HttpMethod.Get, new Uri(specificPersonUrl));
                req.Headers.Add(ApplicationConstant.CACHE_CONTROL, ApplicationConstant.NO_CACHE);
                /*req.Headers.TryAddWithoutValidation("Authorization", authHeader);*/

                // try client add auth header
                client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", authHeader);

                // send
                httpResponse = client.SendAsync(req).Result;

            }
            if (httpResponse.IsSuccessStatusCode)
            {
                string personJsonStr = httpResponse.Content.ReadAsStringAsync().Result;
                return personJsonStr;
            }
            else
            {
                throw new Exception($"api call to {specificPersonUrl} unsuccessful. (StatusCode {httpResponse.StatusCode})");
            }
        }


        internal string DecodeTokenToPerson(string encryptedToken)
        {
            string decodedJson = string.Empty;

            // Decrypt
            var privateKey = _config.GetPrivateKey();
            string plainToken = Jose.JWT.Decode(encryptedToken, privateKey);

            // Verify
            var publicKey = _config.GetPublicKey();

            if (MyInfoSecurityHelper.VerifyToken(plainToken, publicKey))
            {
                var jsonObject = MyInfoSecurityHelper.DecodeToken(plainToken);
                decodedJson = jsonObject.ToString();
            }
            else
            {
                Console.WriteLine($"{nameof(DecodeTokenToPerson)} Failed to verify using MyInfo's public certificate. Call MyInfoConnectorConfig.GetCertificateInfo() to confirm certificate details");
            }

            return decodedJson;
        }
    }
}

