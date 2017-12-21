using AspNet.Security.OAuth.Validation;
using AspNet.Security.OpenIdConnect.Primitives;
using AuthorizationServerV5.Middleware;
using AuthorizationServerV5.Mongo;
using AuthorizationServerV5.Mongo.Contracts;
using AuthorizationServerV5.Mongo.OpenIddictManagers;
using AuthorizationServerV5.Mongo.OpenIddictStores;
using AuthorizationServerV5.Mongo.OpenIddictStores.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Core;
using OpenIddict.Models;

namespace AuthorizationServerV5
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();

            services.AddScoped<IMongoDbContext, MongoDbContext>();
            services.AddScoped<IUserStore<PropyUser>, UserStore<PropyUser>>();
            services.AddScoped<IRoleStore<ApplicationRole>, RoleStore<ApplicationRole>>();

            services.AddScoped<OpenIddictApplication<string>>(x =>
            {
                return new OpenIddictApplication<string>();
            });
            services.AddScoped<OpenIddictAuthorization<string>>(x =>
            {
                return new OpenIddictAuthorization<string>();
            });
            services.AddScoped<OpenIddictScope<string>>(x =>
            {
                return new OpenIddictScope<string>();
            });
            services.AddScoped<OpenIddictToken<string>>(x =>
            {
                return new OpenIddictToken<string>();
            });

            services.AddScoped<IOpenIddictApplicationStore<Application>, ApplicationStore<Application>>();
            services.AddScoped<IOpenIddictAuthorizationStore<Authorization>, AuthorizationStore<Authorization>>();
            services.AddScoped<IOpenIddictScopeStore<Scope>, ScopeStore<Scope>>();
            services.AddScoped<IOpenIddictTokenStore<Token>, TokenStore<Token>>();

            //services.AddScoped<OpenIddictApplicationManager<Application>>();
            services.AddScoped<OpenIddictAuthorizationManager<Authorization>>();
            services.AddScoped<OpenIddictScopeManager<Scope>>();
            services.AddScoped<OpenIddictTokenManager<Token>>();

            services.AddScoped<ApplicationManager<Application>>();
            //services.AddTransient<OpenIddictHandler>(() => { return new MyClass(); });

            services.AddIdentity<PropyUser, ApplicationRole>()
                .AddUserStore<UserStore<PropyUser>>()
                .AddRoleStore<RoleStore<ApplicationRole>>()
                .AddDefaultTokenProviders();

            services.Configure<IdentityOptions>(options =>
            {
                options.ClaimsIdentity.UserNameClaimType = OpenIdConnectConstants.Claims.Name;
                options.ClaimsIdentity.UserIdClaimType = OpenIdConnectConstants.Claims.Subject;
                options.ClaimsIdentity.RoleClaimType = OpenIdConnectConstants.Claims.Role;
            });

            services.AddOpenIddict<Application, Authorization, Scope, Token>(options =>
            {
                options.AddMvcBinders();

                options.AddApplicationStore<ApplicationStore<Application>>();
                options.AddAuthorizationStore<AuthorizationStore<Authorization>>();
                options.AddScopeStore<ScopeStore<Scope>>();
                options.AddTokenStore<TokenStore<Token>>();
                options.AddApplicationManager<ApplicationManager<Application>>();

                //options.Configure(o =>
                //{
                //    o.Provider.OnExtractTokenRequest = context =>
                //    {
                //        //if (string.IsNullOrEmpty(context.Request.Username))
                //        {
                //            context.Request.Username = "RandomUser";
                //        }

                //        //if (context.Request.Password == null)
                //        {
                //            context.Request.Password = "RandomPassword";
                //        }

                //        return Task.CompletedTask;
                //    };
                //});

                //options.EnableAuthorizationEndpoint("/connect/authorize");
                //options.EnableLogoutEndpoint("/connect/logout");
                options.EnableTokenEndpoint("/token");
                options.AllowPasswordFlow()
                    .AllowRefreshTokenFlow()
                    .AllowCustomFlow("urn:ietf:params:oauth:grant-type:facebook_access_token")
                    .AllowCustomFlow("urn:ietf:params:oauth:grant-type:google_identity_token");
                // Dev
                options.DisableHttpsRequirement();
            });

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = OAuthValidationDefaults.AuthenticationScheme;
            })
                .AddOAuthValidation();

            services.AddAuthentication()
                .AddFacebook(options =>
                {
                    options.AppId = Configuration["Authentication:Facebook:AppId"];
                    options.AppSecret = Configuration["Authentication:Facebook:AppSecret"];
                })
                .AddGoogle(options =>
                {
                    options.ClientId = Configuration["Authentication:Google:ClientId"];
                    options.ClientSecret = Configuration["Authentication:Google:ClientSecret"];
                });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
            }

            //app.Use(async (context, next) =>
            //{
            //    // Check if path is /token
            //    if (context.Request.Path != "/token")
            //    {
            //        await next.Invoke();
            //    }

            //    // Check if content type is url encoded
            //    if (context.Request.ContentType != "application/x-www-form-urlencoded")
            //    {
            //        await next.Invoke();
            //    }

            //    // Read request body
            //    var request = context.Request;
            //    var stream = request.Body;
            //    var body = new StreamReader(stream).ReadToEnd();
            //    body += "&";

            //    // Check grant type is password
            //    if (!body.Contains("grant_type=password"))
            //    {
            //        await next.Invoke();
            //    }

            //    // Change username or password if they are empty
            //    if (body.Contains("username=&"))
            //    {
            //        body = body.Replace("username=&", "username=AnonomysUser&");
            //    }

            //    if (body.Contains("password=&"))
            //    {
            //        body = body.Replace("password=&", "password=AnonomysPassword&");
            //    }

            //    var modifiedBody = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded");
            //    stream = await modifiedBody.ReadAsStreamAsync();
            //    request.Body = stream;

            //    await next.Invoke();
            //});
            app.UsePasswordFlowMiddleware();

            app.UseAuthentication();

            app.UseMvc();
        }
    }
}