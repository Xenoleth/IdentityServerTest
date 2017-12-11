using Newtonsoft.Json;
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace AuthorizationServerV5.Facebook
{
    public class FacebookClient : IFacebookClient
    {
        private readonly HttpClient httpClient;

        public FacebookClient()
        {
            // TODO: Add Dependency injection
            this.httpClient = new HttpClient()
            {
                BaseAddress = new Uri("https://graph.facebook.com/v2.11/")
            };

            this.httpClient.DefaultRequestHeaders
                .Accept
                .Add(new MediaTypeWithQualityHeaderValue("application/json"));
        }

        public async Task<T> GetAsync<T>(string accessToken, string endpoint, string args = null)
        {
            var response = await this.httpClient.GetAsync($"{endpoint}?access_token={accessToken}&{args}");
            if (!response.IsSuccessStatusCode)
            {
                return default(T);
            }

            var result = await response.Content.ReadAsStringAsync();

            return JsonConvert.DeserializeObject<T>(result);
        }
    }
}
