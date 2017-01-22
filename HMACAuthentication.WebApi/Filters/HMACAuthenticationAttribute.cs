using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.Filters;
using System.Web.Http.Results;

namespace HMACAuthentication.WebApi.Filters
{
    public class HmacAuthenticationAttribute : Attribute, IAuthenticationFilter
    {
        private static Dictionary<string, string> allowedApps = new Dictionary<string, string>();
        private readonly UInt64 requestMaxAgeInSeconds = 300;  //5 mins
        private readonly string authenticationScheme = "amx";

        public HmacAuthenticationAttribute()
        {
            if (allowedApps.Count == 0)
            {
                allowedApps.Add("4d53bce03ec34c0a911182d4c228ee6c", "A93reRTUJHsCuQSHR+L3GxqOJyDmQpCgps102ciuabc=");
            }
        }

        public bool AllowMultiple
        {
            get
            {
                return false;
            }
        }

        public Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            var req = context.Request;

            if (req.Headers.Authorization != null && authenticationScheme.Equals(req.Headers.Authorization.Scheme, StringComparison.OrdinalIgnoreCase))
            {
                var rawAuthorizeHeader = req.Headers.Authorization.Parameter;

                var autherizationHeaderArray = GetAutherizationHeaderValues(rawAuthorizeHeader);

                if (autherizationHeaderArray != null)
                {
                    var appId = autherizationHeaderArray[0];
                    var inComingBase64String = autherizationHeaderArray[1];
                    var nonce = autherizationHeaderArray[2];
                    var requestTimeStamp = autherizationHeaderArray[3];

                    var isValid = IsValidRequest(req, appId, inComingBase64String, nonce, requestTimeStamp);

                    if (isValid.Result)
                    {
                        var currentPrincipal = new GenericPrincipal(new GenericIdentity(appId), null);
                        context.Principal = currentPrincipal;
                    }
                    else
                    {
                        context.ErrorResult = new UnauthorizedResult(new AuthenticationHeaderValue[0], context.Request);
                    }

                }
                else
                {
                    context.ErrorResult = new UnauthorizedResult(new AuthenticationHeaderValue[0], context.Request);
                }
            }
            else
            {
                context.ErrorResult = new UnauthorizedResult(new AuthenticationHeaderValue[0], context.Request);
            }

            return Task.FromResult(0);
        }

        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            context.Result = new ResultWithChallenge(context.Result);
            return Task.FromResult(0);
        }



        private async Task<bool> IsValidRequest(HttpRequestMessage req, string appId, string inComingBase64String, string nonce, string requestTimeStamp)
        {
            string requestContentBase64String = "";

            string requestUri = HttpUtility.UrlEncode(req.RequestUri.AbsoluteUri.ToLower());

            string requestMethod = req.Method.Method;

            if (!allowedApps.ContainsKey(appId))
            {
                return false;
            }

            var sharedKey = allowedApps[appId];

            var contentStr = await req.Content.ReadAsStringAsync();
            var requestContentBytesArray = await req.Content.ReadAsByteArrayAsync();

            MD5 md5 = MD5.Create();
            var md5HashArray = md5.ComputeHash(requestContentBytesArray);

            requestContentBase64String = Convert.ToBase64String(md5HashArray);

            string data = $"{appId}{requestMethod}{requestUri}{requestTimeStamp}{nonce}{requestContentBase64String}";

            byte[] signature = Encoding.UTF8.GetBytes(data);

            var secretKey = Convert.FromBase64String(sharedKey);

            using (var hmac = new HMACSHA256(secretKey))
            {
                byte[] signatureBytes = hmac.ComputeHash(signature);
                string outComingBase64String = Convert.ToBase64String(signatureBytes);
                return inComingBase64String.Equals(outComingBase64String, StringComparison.OrdinalIgnoreCase);
            }

        }


        private string[] GetAutherizationHeaderValues(string rawAuthHeader)
        {
            var authArray = rawAuthHeader.Split(':');
            if (authArray.Length == 4)
            {
                return authArray;
            }
            return null;
        }
    }

    public class ResultWithChallenge : IHttpActionResult
    {
        private readonly string authenticationScheme = "amx";
        private readonly IHttpActionResult _next;


        public ResultWithChallenge(IHttpActionResult next)
        {
            this._next = next;
        }
        public async Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            var response = await _next.ExecuteAsync(cancellationToken);
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue(authenticationScheme));
            }

            return response;
        }
    }
}