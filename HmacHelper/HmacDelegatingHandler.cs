using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace HmacHelper
{
    public class HmacDelegatingHandler : DelegatingHandler
    {
        //Obtained from the server earlier!
        private string _apiKey = "";
        private string _apiSecret;
        private string _scheme = "HMAC";

        public string ApiKey
        {
            private get { return _apiKey; }
            set { _apiKey = value; }
        }

        public string ApiSecret
        {
            private get { return _apiSecret;}
            set { _apiSecret = value; }
        }

        public string Scheme
        {
            private get { return _scheme; }
            set { _scheme = value; }
        }

        public HmacDelegatingHandler(string apiKey, string apiSecret, string scheme = "HMAC")
        {
            ApiKey = apiKey;
            ApiSecret = apiSecret;
            Scheme = scheme;

        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {

            HttpResponseMessage response = null;
            string requestContentBase64String = string.Empty;

            string requestUri = HttpUtility.UrlEncode(request.RequestUri.AbsoluteUri.ToLower());

            string requestHttpMethod = request.Method.Method;

            //Calculate UNIX time
            DateTime epochStart = new DateTime(1970, 01, 01, 0, 0, 0, 0, DateTimeKind.Utc);
            TimeSpan timeSpan = DateTime.UtcNow - epochStart;
            string requestTimeStamp = Convert.ToUInt64(timeSpan.TotalSeconds).ToString();

            //create random nonce for each request
            string nonce = Guid.NewGuid().ToString("N");

            //Checking if the request contains body, usually will be null wiht HTTP GET and DELETE
            if (request.Content != null)
            {
                byte[] content = await request.Content.ReadAsByteArrayAsync();
                MD5 md5 = MD5.Create();
                //Hashing the request body, any change in request body will result in different hash, we'll incure message integrity
                byte[] requestContentHash = md5.ComputeHash(content);
                requestContentBase64String = Convert.ToBase64String(requestContentHash);
            }

            //Creating the raw signature string
            string signatureRawData = String.Format("{0}{1}{2}{3}{4}{5}", ApiKey, requestHttpMethod, requestUri, requestTimeStamp, nonce, requestContentBase64String);

            var secretKeyByteArray = Convert.FromBase64String(ApiSecret);

            byte[] signature = Encoding.UTF8.GetBytes(signatureRawData);

            using (HMACSHA256 hmac = new HMACSHA256(secretKeyByteArray))
            {
                byte[] signatureBytes = hmac.ComputeHash(signature);
                string requestSignatureBase64String = Convert.ToBase64String(signatureBytes);
                //Setting the values in the Authorization header using custom scheme

                request.Headers.Add(Scheme, string.Format("{0}:{1}:{2}:{3}", ApiKey, requestSignatureBase64String, nonce, requestTimeStamp));
            }

            response = await base.SendAsync(request, cancellationToken);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                return response;
            }

            var valid = _validResponse(response);

            return response;
        }

        private bool _validResponse(HttpResponseMessage response)
        {
            if (response.Content.Headers.Contains(Scheme))
            {
                return false;
            }

            IEnumerable<string> authHeader = new List<string>();

            var success = response.Headers.TryGetValues(Scheme, out authHeader);

            if (!success)
            {
                return false;
            }

            var autherizationHeaderArray = GetAuthorizationHeaderValues(authHeader.ElementAt(0));

            var apiKey = autherizationHeaderArray[0];
            var incomingBase64Signature = autherizationHeaderArray[1];
            var nonce = autherizationHeaderArray[2];
            var timeStamp = autherizationHeaderArray[3];

            var isValid = _isValidResponse(response, apiKey, incomingBase64Signature, nonce, timeStamp);

            if (!isValid.Result)
            {
                return false;
            }

            string responseString = response.Content.ReadAsStringAsync().Result;
            return true;
        }

        private string[] GetAuthorizationHeaderValues(string rawAuthzHeader)
        {

            var credArray = rawAuthzHeader.Split(':');

            if (credArray.Length == 4)
            {
                return credArray;
            }
            else
            {
                return null;
            }

        }

        private async Task<bool> _isValidResponse(HttpResponseMessage response, string apiKey, string incomingBase64Signature, string nonce, string timeStamp)
        {
            string responseContentBase64String = "";
            string requestUri = HttpUtility.UrlEncode(response.RequestMessage.RequestUri.AbsoluteUri.ToLower());

            var responseStatusCodeBytes = Encoding.UTF8.GetBytes(response.StatusCode.ToString());

            var base64StatusCodeString = Convert.ToBase64String(responseStatusCodeBytes);


            byte[] hash = await _computeHash(response.Content);

            if (hash != null)
            {
                responseContentBase64String = Convert.ToBase64String(hash);
            }

            string data = String.Format("{0}{1}{2}{3}{4}{5}", apiKey, base64StatusCodeString, requestUri, timeStamp, nonce, responseContentBase64String);

            var secretKeyBytes = Convert.FromBase64String(ApiSecret);

            byte[] signature = Encoding.UTF8.GetBytes(data);

            using (HMACSHA256 hmac = new HMACSHA256(secretKeyBytes))
            {
                byte[] signatureBytes = hmac.ComputeHash(signature);

                return (incomingBase64Signature.Equals(Convert.ToBase64String(signatureBytes), StringComparison.Ordinal));
            }

        }

        private async Task<byte[]> _computeHash(HttpContent httpContent)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] hash = null;
                var content = await httpContent.ReadAsByteArrayAsync();
                if (content.Length != 0)
                {
                    hash = md5.ComputeHash(content);
                }
                return hash;
            }
        }
    }
}
