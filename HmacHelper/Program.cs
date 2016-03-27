using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace HmacHelper
{
    class Program
    {
        private const string URL = "https://sub.domain.com/objects.json";
        private const string urlParameters = "";

        static void Main(string[] args)
        {
            var hmachandler = new HmacDelegatingHandler("apiKey", "secret", "HMAC");

            using (var client = new HttpClient(hmachandler))
            {
                client.BaseAddress = new Uri(URL);

                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));


                // List data response.
                var response = client.GetAsync(urlParameters).Result; // Blocking call!
                if (response.IsSuccessStatusCode)
                {
                    // Parse the response body. Blocking!
                    var body = response.Content.ReadAsStringAsync().Result;
                    Console.WriteLine(body);
                }
                else
                {
                    Console.WriteLine("{0} ({1})", (int) response.StatusCode, response.ReasonPhrase);
                }
            }
        }
    }
}
