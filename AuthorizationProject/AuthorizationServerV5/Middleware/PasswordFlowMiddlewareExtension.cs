using Microsoft.AspNetCore.Builder;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthorizationServerV5.Middleware
{
    public static class PasswordFlowMiddlewareExtension
    {
        public static IApplicationBuilder UsePasswordFlowMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<PasswordFlowMiddleware>();
        }
    }
}
