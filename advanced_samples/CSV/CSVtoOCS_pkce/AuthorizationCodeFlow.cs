using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using IdentityModel.Client;
using IdentityModel.OidcClient;
using IdentityModel.OidcClient.Browser;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;

namespace CSVtoOCS
{
    //
    // Summary:
    //     DelegatingHandler to assist with authenticating with Identity Server.
    public class AuthenticationHandler_PKCE : DelegatingHandler
    {
        private string accessToken = null;
        private DateTime expiration = DateTime.MinValue;

        private string _clientId = null;

        private string _scope = null;

        private string _tenantId = null;

        public AuthenticationHandler_PKCE(string tenantId, string clientId, string scope = "openid ocsapi")
        {
            _tenantId = tenantId;
            _clientId = clientId;
            _scope = scope
                ;
            AuthorizationCodeFlow.OcsUrl = "https://dat-b.osisoft.com";
            AuthorizationCodeFlow.RedirectHost = "https://127.0.0.1";
            AuthorizationCodeFlow.RedirectPort = 54567;
            AuthorizationCodeFlow.RedirectPath = "signin-oidc";


            SystemBrowser.openBrowser = new OpenSystemBrowser();
            // Get access token.

        }
    

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        { 
            if (accessToken == null || expiration.AddSeconds(5) < DateTime.Now)
            {
                (accessToken, expiration) =
                    AuthorizationCodeFlow.GetAuthorizationCodeFlowAccessToken(_clientId, _scope, _tenantId);
            }

            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer" , accessToken);


            return base.SendAsync(request, cancellationToken);
        }
    }

    public static class AuthorizationCodeFlow
    {
        private static OidcClient _oidcClient;
        private static string _ocsIdentityUrl;
        private static string _redirectHost;
        private static int _redirectPort;
        private static string _redirectPath;

        public static string OcsUrl
        {
            set => _ocsIdentityUrl = value + IdentityResourceSuffix;
        }

        public static string RedirectHost
        {
            set => _redirectHost = value;
        }

        public static int RedirectPort
        {
            set => _redirectPort = value;
        }

        public static string RedirectPath
        {
            set => _redirectPath = value;
        }

        /// <summary>
        /// Identity resource suffix.
        /// </summary>
        private const string IdentityResourceSuffix = "/identity";

        public static (string, DateTime) GetAuthorizationCodeFlowAccessToken(string clientId, string scope, string tenantId)
        {
            Console.WriteLine("+-----------------------+");
            Console.WriteLine("|  Sign in with OIDC    |");
            Console.WriteLine("+-----------------------+");
            Console.WriteLine("");

            LoginResult loginResult = null;
            do
            {
                if (loginResult != null)
                {
                    Console.WriteLine(loginResult.Error);
                    return (string.Empty, DateTime.Now);
                }

                Console.WriteLine("Prompting for login via a browser...");
                loginResult = SignIn(clientId, scope, tenantId).Result;
            } while (loginResult.IsError);


            return (loginResult.AccessToken, loginResult.AccessTokenExpiration.ToLocalTime());
        }

        private static async Task<ProviderInformation> GetProviderInformation()
        {
            // Discover endpoints from metadata.
            using (HttpClient client = new HttpClient())
            {
                // Create a discovery request
                var discoveryDocumentRequest = new DiscoveryDocumentRequest
                {
                    Address = _ocsIdentityUrl,
                    Policy = new DiscoveryPolicy
                    {
                        ValidateIssuerName = false
                    }
                };

                var discoveryResponse =
                    await client.GetDiscoveryDocumentAsync(discoveryDocumentRequest);

                return discoveryResponse.IsError
                    ? throw new Exception($"Error while getting the discovery document: {discoveryResponse.Error}")
                    : new ProviderInformation()
                    {
                        IssuerName = discoveryResponse.Issuer,
                        KeySet = discoveryResponse.KeySet,
                        AuthorizeEndpoint = discoveryResponse.AuthorizeEndpoint,
                        TokenEndpoint = discoveryResponse.TokenEndpoint,
                        EndSessionEndpoint = discoveryResponse.EndSessionEndpoint,
                        UserInfoEndpoint = discoveryResponse.UserInfoEndpoint,
                        TokenEndPointAuthenticationMethods =
                            discoveryResponse.TokenEndpointAuthenticationMethodsSupported
                    };
            }
        }

        private static async Task<LoginResult> SignIn(string clientId, string scope, string tenantId)
        {
            // create a redirect URI using an available port on the loopback address.
            // requires the OP to allow random ports on 127.0.0.1 - otherwise set a static port
            var browser = new SystemBrowser(_redirectPort);
            var redirectUri = string.Format($"{_redirectHost}:{browser.Port}/{_redirectPath}");
            try
            {
                // Create the OICD client Options
                var options = new OidcClientOptions
                {
                    Authority = _ocsIdentityUrl,
                    ClientId = clientId,
                    RedirectUri = redirectUri,
                    Scope = scope,
                    FilterClaims = false,
                    Flow = OidcClientOptions.AuthenticationFlow.AuthorizationCode,
                    Browser = browser,
                    Policy = new Policy
                    {
                        Discovery = new DiscoveryPolicy
                        {
                            ValidateIssuerName = false
                        }
                    },
                };

                _oidcClient = new OidcClient(options);
                var loginRequest = new LoginRequest
                {
                    FrontChannelExtraParameters = new { acr_values = $"tenant:{tenantId}" }
                };

                // Login with the client. This call will open a new tab in your default browser
                return await _oidcClient.LoginAsync(loginRequest);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error while logging in: {ex}");
                throw ex;
            }
        }

        public static async void Logout()
        {
            await _oidcClient.LogoutAsync();
        }
    }

    public interface IOpenBrowser
    {
        void OpenBrowser(string url, string userName, string password);
    }

    public class OpenSystemBrowser : IOpenBrowser
    {
        public void OpenBrowser(string url, string userName, string password)
        {
            try
            {
                Process.Start(url);
            }
            catch
            {
                // hack because of this: https://github.com/dotnet/corefx/issues/10361
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    url = url.Replace("&", "^&");
                    Process.Start(new ProcessStartInfo("cmd", $"/c start {url}") { CreateNoWindow = true });
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    Process.Start("xdg-open", url);
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    Process.Start("open", url);
                }
                else
                {
                    throw;
                }
            }
        }
    }

    public class SystemBrowser : IBrowser
    {
        public int Port { get; }
        private readonly string _path;
        public static string userName;
        public static string password;
        public static IOpenBrowser openBrowser;

        public SystemBrowser(int? port = null, string path = null)
        {
            _path = path;

            if (!port.HasValue)
            {
                Port = GetRandomUnusedPort();
            }
            else
            {
                Port = port.Value;
            }
        }

        private int GetRandomUnusedPort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        public async Task<BrowserResult> InvokeAsync(BrowserOptions options)
        {
            using (var listener = new LoopbackHttpListener(Port, _path))
            {
                openBrowser.OpenBrowser(options.StartUrl, userName, password);

                try
                {
                    var result = await listener.WaitForCallbackAsync();
                    if (string.IsNullOrWhiteSpace(result))
                    {
                        return new BrowserResult
                        { ResultType = BrowserResultType.UnknownError, Error = "Empty response." };
                    }

                    return new BrowserResult { Response = result, ResultType = BrowserResultType.Success };
                }
                catch (TaskCanceledException ex)
                {
                    return new BrowserResult { ResultType = BrowserResultType.Timeout, Error = ex.Message };
                }
                catch (Exception ex)
                {
                    return new BrowserResult { ResultType = BrowserResultType.UnknownError, Error = ex.Message };
                }
            }
        }
    }

    public class LoopbackHttpListener : IDisposable
    {
        const int DefaultTimeout = 60 * 5; // 5 mins (in seconds)

        IWebHost _host;
        TaskCompletionSource<string> _source = new TaskCompletionSource<string>();

        public string Url { get; }

        public LoopbackHttpListener(int port, string path = null)
        {
            path = path ?? string.Empty;
            if (path.StartsWith("/")) path = path.Substring(1);

            Url = $"https://127.0.0.1:{port}/{path}";

            _host = new WebHostBuilder()
                .UseKestrel()
                .UseUrls(Url)
                .Configure(Configure)
                .Build();
            _host.Start();
        }

        public void Dispose()
        {
            Task.Run(async () =>
            {
                await Task.Delay(500);
                _host.Dispose();
            });
        }

        void Configure(IApplicationBuilder app)
        {
            app.Run(async ctx =>
            {
                if (ctx.Request.Method == "GET")
                {
                    SetResult(ctx.Request.QueryString.Value, ctx);
                }
                else if (ctx.Request.Method == "POST")
                {
                    if (!ctx.Request.ContentType.Equals("application/x-www-form-urlencoded",
                        StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.Response.StatusCode = 415;
                    }
                    else
                    {
                        using (var sr = new StreamReader(ctx.Request.Body, Encoding.UTF8))
                        {
                            var body = await sr.ReadToEndAsync();
                            SetResult(body, ctx);
                        }
                    }
                }
                else
                {
                    ctx.Response.StatusCode = 405;
                }
            });
        }

        private void SetResult(string value, HttpContext ctx)
        {
            try
            {
                ctx.Response.StatusCode = 200;
                ctx.Response.ContentType = "text/html";
                ctx.Response.WriteAsync("<h1>You can now return to the application.</h1>");
                ctx.Response.Body.Flush();

                _source.TrySetResult(value);
            }
            catch
            {
                ctx.Response.StatusCode = 400;
                ctx.Response.ContentType = "text/html";
                ctx.Response.WriteAsync("<h1>Invalid request.</h1>");
                ctx.Response.Body.Flush();
            }
        }

        public Task<string> WaitForCallbackAsync(int timeoutInSeconds = DefaultTimeout)
        {
            Task.Run(async () =>
            {
                await Task.Delay(timeoutInSeconds * 1000);
                _source.TrySetCanceled();
            });

            return _source.Task;
        }
    }
}
