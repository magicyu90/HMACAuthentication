﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using Newtonsoft.Json;

namespace HMACAuthentication.Client
{
    class Program
    {
        static void Main(string[] args)
        {

            Console.WriteLine("type A to launch the client,type Q to quit");

            bool b = true;
            while (b)
            {
                Console.WriteLine("Input the numer.....");

                ConsoleKeyInfo key = Console.ReadKey();

                switch (key.Key)
                {
                    case ConsoleKey.A:
                        RunAsync().Wait();
                        break;
                    case ConsoleKey.Q:
                        b = false;
                        break;
                }
            }

        }


        private static async Task RunAsync()
        {

            Console.WriteLine("Calling the back-end api");

            string baseAddress = "http://localhost:62599";
            var handler = new CustomDelegatingHandler();

            var client = HttpClientFactory.Create(handler);

            var order = new Order
            {
                OrderId = 1234,
                CustomerName = "Hugo",
                IsShipped = true,
                ShipperCity = "Paris"
            };

            string str = JsonConvert.SerializeObject(order);

            var response = await client.PostAsJsonAsync(baseAddress + "/api/orders", order);

            if (response.IsSuccessStatusCode)
            {
                string responseString = await response.Content.ReadAsStringAsync();

                Console.WriteLine("responseString:" + responseString);
            }
            else
            {
                Console.WriteLine("Failed to call the api,http status code:{0}, failed reasion:{1}", response.StatusCode, response.ReasonPhrase);

            }
            Console.ReadKey();
        }

        private static void GenerateAppKey()
        {
            using (var cryptProvider = new RNGCryptoServiceProvider())
            {

                byte[] secretKey = new byte[32];
                cryptProvider.GetBytes(secretKey);

                var apiKey = Convert.ToBase64String(secretKey);

                Console.WriteLine("apiKey:" + apiKey);
            }
        }

    }

    public class CustomDelegatingHandler : DelegatingHandler
    {
        private string APPId = "4d53bce03ec34c0a911182d4c228ee6c";
        private string APIKey = "A93reRTUJHsCuQSHR+L3GxqOJyDmQpCgps102ciuabc=";

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            HttpResponseMessage response = null;
            string requestContentString = string.Empty;

            string requestUri = HttpUtility.UrlEncode(request.RequestUri.AbsoluteUri.ToLower());
            string requestMethod = request.Method.Method;

            long utcRequest = UnixTime.ToUnixTime(DateTime.UtcNow);

            //random nonce
            string nonce = Guid.NewGuid().ToString("N");

            if (request.Content != null)
            {
                string contentStr = await request.Content.ReadAsStringAsync();
                byte[] content = await request.Content.ReadAsByteArrayAsync();
                MD5 md5 = MD5.Create();
                byte[] requestContentHash = md5.ComputeHash(content);
                requestContentString = Convert.ToBase64String(requestContentHash);
            }

            string signatureRawData = $"{APPId}{requestMethod}{requestUri}{utcRequest}{nonce}{requestContentString}";

            byte[] signatureBytesArray = Encoding.UTF8.GetBytes(signatureRawData);

            byte[] secretBytesArray = Convert.FromBase64String(APIKey);


            using (var hmac = new HMACSHA256(secretBytesArray))
            {
                string requestSignatureBase64String = Convert.ToBase64String(hmac.ComputeHash(signatureBytesArray));

                request.Headers.Authorization = new AuthenticationHeaderValue("amx", $"{APPId}:{requestSignatureBase64String}:{nonce}:{utcRequest}");
            }

            response = await base.SendAsync(request, cancellationToken);

            return response;
        }
    }
}
