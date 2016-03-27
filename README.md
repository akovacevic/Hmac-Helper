# Hmac-Helper
DelegatingHandler to automatically add HMAC header to all your HttpRequestMessages

            var hmachandler = new HmacDelegatingHandler("apiKey", "secret", "HMAC");
            using (var client = new HttpClient(hmachandler))
            {
                //call api here
            }