using Microsoft.AspNetCore.Http;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace AuthorizationServerV5.Middleware
{
    public class PasswordFlowMiddleware
    {
        private readonly RequestDelegate next;

        public PasswordFlowMiddleware(RequestDelegate next)
        {
            this.next = next;
        }

        public async Task Invoke(HttpContext context)
        {

            // Check if path is /token
            if (context.Request.Path != "/token")
            {
                await this.next(context);
            }

            // Check if content type is url encoded
            if (context.Request.ContentType != "application/x-www-form-urlencoded")
            {
                await this.next(context);
            }

            // Read request body
            var request = context.Request;
            var stream = request.Body;
            var body = new StreamReader(stream).ReadToEnd();
            body += "&scope=offline_access&";
                        
            // Check grant type is password
            if (!body.Contains("grant_type=password"))
            {
                await this.next(context);
            }

            // Change username or password if they are empty
            if (body.Contains("username=&"))
            {
                body = body.Replace("username=&", "username=AnonomysUser&");
            }

            if (body.Contains("password=&"))
            {
                body = body.Replace("password=&", "password=AnonomysPassword&");
            }

            var modifiedBody = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded");
            stream = await modifiedBody.ReadAsStreamAsync();
            request.Body = stream;

            await this.next(context);
        }
    }
}
