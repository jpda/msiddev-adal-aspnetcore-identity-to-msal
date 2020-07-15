/************************************************************************************************
The MIT License (MIT)

Copyright (c) 2015 Microsoft Corporation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
***********************************************************************************************/

using OAuth2_UserIdentity.Models;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Newtonsoft.Json;
using Microsoft.Identity.Client;
using Microsoft.AspNet.Identity;

namespace OAuth2_UserIdentity.Controllers
{
    [Authorize]
    public class UserProfileController : Controller
    {
        //
        // GET: /UserProfile/
        public async Task<ActionResult> Index(string authError)
        {
            UserProfile profile = null;
            bool reauth = false;
            AuthenticationResult result = null;

            var claimsIdentity = (ClaimsIdentity)ClaimsPrincipal.Current?.Identity;
            var userObjectID = claimsIdentity.FindFirstValue("http://schemas.microsoft.com/identity/claims/objectidentifier");
            var tenantId = claimsIdentity.FindFirstValue("http://schemas.microsoft.com/identity/claims/tenantid");

            var cacheKey = $"{userObjectID}.{tenantId}";

            try
            {
                var msalClient = ConfidentialClientApplicationBuilder
                        .Create(Startup.clientId)
                        .WithClientSecret(Startup.clientSecret)
                        .WithAuthority(Startup.Authority)
                        .WithRedirectUri(Startup.redirectUrl)
                        .Build();
                var msalCache = new MSALPerUserMemoryTokenCache(msalClient.UserTokenCache);

                var msalAccount = await msalClient.GetAccountAsync(cacheKey);

                var graphTokenRequest = msalClient.AcquireTokenSilent(new[] { "User.Read" }, msalAccount);
                result = await graphTokenRequest.ExecuteAsync();
            }
            catch (MsalUiRequiredException)
            {
                reauth = true;
            }
            catch (Exception e)
            {
                ViewBag.ErrorMessage = e.Message;
                return View("Error");
            }

            // don't new up a new http client
            // use the graph SDK if you like libraries

            try
            {
                //
                // Call the Graph API and retrieve the user's profile.
                //
                string requestUrl = Startup.graphUserUrl;
                HttpClient client = new HttpClient();
                HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);
                HttpResponseMessage response = await client.SendAsync(request);

                //
                // Return the user's profile in the view.
                //
                if (response.IsSuccessStatusCode)
                {
                    string responseString = await response.Content.ReadAsStringAsync();
                    profile = JsonConvert.DeserializeObject<UserProfile>(responseString);
                    return View(profile);
                }
                else if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    ////
                    //// If the call failed, then drop the current access token and show the user an error indicating they might need to sign-in again.
                    ////
                    ////authContext.TokenCache.Clear();

                    //Uri redirectUri = new Uri(Request.Url.GetLeftPart(UriPartial.Authority).ToString() + "/OAuth");
                    //string state = GenerateState(userObjectID, Request.Url.ToString());
                    //ViewBag.AuthorizationUrl = await authContext.GetAuthorizationRequestUrlAsync(Startup.graphResourceId, Startup.clientId, redirectUri, UserIdentifier.AnyUser, state == null ? null : "&state=" + state);

                    //profile = new UserProfile();
                    //profile.DisplayName = " ";
                    //profile.GivenName = " ";
                    //profile.Surname = " ";
                    //ViewBag.ErrorMessage = "UnexpectedError";
                    //return View(profile);
                }

                ViewBag.ErrorMessage = "Error Calling Graph API.";
                return View("Error");
            }
            catch
            {
                ViewBag.ErrorMessage = "Error Calling Graph API.";
                return View("Error");
            }
        }

        /// Generate a state value using a random Guid value and the origin of the request.
        /// The state value will be consumed by the OAuth controller for validation and redirection after login.
        /// Here we store the random Guid in the database cache for validation by the OAuth controller.
        public string GenerateState(string userObjId, string requestUrl)
        {
            try
            {
                string stateGuid = Guid.NewGuid().ToString();
                ApplicationDbContext db = new ApplicationDbContext();
                db.UserStateValues.Add(new UserStateValue { stateGuid = stateGuid, userObjId = userObjId });
                db.SaveChanges();

                List<String> stateList = new List<String>();
                stateList.Add(stateGuid);
                stateList.Add(requestUrl);

                var stream = new MemoryStream();

                DataContractSerializer ser = new DataContractSerializer(typeof(List<String>));
                ser.WriteObject(stream, stateList);

                var stateBits = stream.ToArray();

                return Url.Encode(Convert.ToBase64String(stateBits));
            }
            catch
            {
                return null;
            }

        }
    }
}