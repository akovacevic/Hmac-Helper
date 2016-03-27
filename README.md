# Hmac-Helper
DelegatingHandler to automatically add HMAC header to all your HttpRequestMessages

            var hmacHandler = new HmacDelegatingHandler("apiKey", "secret", "HMAC");
            using (var client = new HttpClient(hmacHandler))
            {
                //call api here
            }