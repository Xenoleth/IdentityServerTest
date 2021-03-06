﻿using AuthorizationServerV2.Extensions;
using AuthorizationServerV2.Repository;
using AuthorizationServerV2.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Cors.Internal;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AuthorizationServerV2
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddCors(options =>
            {
                options.AddPolicy("CorsPolicy", builder =>
                    builder.WithOrigins("http://localhost:5003/")
                        .AllowAnyOrigin()
                        .AllowAnyMethod()
                        .AllowAnyHeader()
                        .AllowCredentials());
            });

            services.AddIdentityServer()
                .AddMongoRepository()
                .AddMongoDbForAspIdentity<External.IdentityUser, External.IdentityRole>(Configuration)
                .AddClients()
                .AddIdentityApiResources()
                .AddPersistedGrants()
                .AddCorsPolicyService<CorsPolicyService>()
                .AddProfileService<ProfileService>()
                .AddAspNetIdentity<External.IdentityUser>();

            services.AddMvc();
            services.Configure<MvcOptions>(options =>
            {
                options.Filters.Add(new CorsAuthorizationFilterFactory("CorsPolicy"));
            });
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseCors("CorsPolicy");
            app.UseMongoDbForIdentityServer();
            app.UseAuthentication();
            app.UseIdentityServer();

            app.UseMvc();

            // TODO: Temporary
            app.UseStaticFiles();
            app.UseMvcWithDefaultRoute();
        }
    }
}
