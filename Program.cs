﻿using Auth0.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SampleMvcApp.Support;
using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Logging;

var builder = WebApplication.CreateBuilder(args);

//To use MVC we have to explicitly declare we are using it. Doing so will prevent a System.InvalidOperationException.
builder.Services.AddControllersWithViews();
builder.Services.AddAuth0WebAppAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.ClientId = builder.Configuration["Auth0:ClientId"];
    options.ClientSecret = builder.Configuration["Auth0:ClientSecret"];
    ;
}).WithAccessToken(options =>
{
    options.Scope = "openid profile email offline_access";
    options.UseRefreshTokens = true;
    options.Events = new Auth0WebAppWithAccessTokenEvents
    {
        OnMissingAccessToken = async (context) =>
        {
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            var authenticationProperties = new LoginAuthenticationPropertiesBuilder().WithRedirectUri("/").Build();
            await context.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
        },
        OnMissingRefreshToken = async (context) =>
        {
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            var authenticationProperties = new LoginAuthenticationPropertiesBuilder().WithRedirectUri("/").Build();
            await context.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
        }
    };
});

// Configure the HTTP request pipeline.
builder.Services.ConfigureSameSiteNoneCookies();
var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseStaticFiles();
app.UseCookiePolicy();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseEndpoints(endpoints =>
{
    endpoints.MapDefaultControllerRoute();
});

app.Run();