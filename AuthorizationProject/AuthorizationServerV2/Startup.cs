using AuthorizationServerV2.Extensions;
using AuthorizationServerV2.External;
using AuthorizationServerV2.Repository;
using AuthorizationServerV2.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Cors.Internal;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using System;
using System.Collections.Generic;

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

            //services.AddTransient<IdentityErrorDescriber, IdentityErrorDescriber>();
            //services.AddTransient<IUserValidator<External.IdentityUser>, UserValidator<External.IdentityUser>>();
            //services.AddTransient<IPasswordHasher<External.IdentityUser>, PasswordHasher<External.IdentityUser>>();
            //services.AddTransient<IPasswordValidator<External.IdentityUser>, PasswordValidator<External.IdentityUser>>();
            //services.AddTransient<ILookupNormalizer, UpperInvariantLookupNormalizer>();
            //services.AddScoped<UserManager<External.IdentityUser>>(app =>
            //{
            //    return new UserManager<External.IdentityUser>(
            //        app.GetService<IUserStore<External.IdentityUser>>(),
            //        app.GetService<IOptions<IdentityOptions>>(),
            //        app.GetService<IPasswordHasher<External.IdentityUser>>(),
            //        new List<IUserValidator<External.IdentityUser>>()
            //        {
            //            app.GetService<IUserValidator<External.IdentityUser>>()
            //        },
            //        new List<IPasswordValidator<External.IdentityUser>>()
            //        {
            //            app.GetService<IPasswordValidator<External.IdentityUser>>()
            //        },
            //        app.GetService<ILookupNormalizer>(),
            //        app.GetService<IdentityErrorDescriber>(),
            //        app.GetService<IServiceProvider>(),
            //        app.GetService<ILogger<UserManager<External.IdentityUser>>>()
            //    );
            //});
            //services.AddScoped<UserManager<External.IdentityUser>>();

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

            app.UseIdentityServer();
            app.UseMongoDbForIdentityServer();
            app.UseCors("CorsPolicy");

            app.UseMvc();

            // TODO: Temporary
            app.UseStaticFiles();
            app.UseMvcWithDefaultRoute();
        }
    }
}
