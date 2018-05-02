using System;
using System.Collections.Generic;
using System.Web;
using System.IO;
using MapLarge.Engine;
using System.Threading;
using MapLarge.Engine.Import;
using Newtonsoft.Json;
using System.Net;
using System.Net.Http;
using MapLarge.OAuthPlugin;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Specialized;
using System.Security.Principal;
using System.Text;
using MapLarge.Engine.Diagnostics;
using MapLarge.Engine.Unified.Auth;
using plugin = MapLarge.OAuthPlugin;
using System.Linq;

namespace OAuthPluginIntegrationTest {
	[TestClass]
	public class UnitTest1 {
		
		public void TestMethod1() {
		}
	}




	[TestClass]
	
	public class OAuthPluginFixture {
		private static readonly object ForceSingleThreadedTestsLock = new object();

		static Core _core;
		private static string _confFileName;

		public OAuthPluginFixture() {
			ImportManager.__downloadGDALOnStartup = false;
		}

		public static string FileBasePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "IntegrationTestCores");
		private static  plugin.OAuthPlugin.OAuthPluginConfig newConfig = new plugin.OAuthPlugin.OAuthPluginConfig();

		[ClassInitialize]
		public static void TestFixtureSetup(TestContext context) {
			// Clean what could have been a previous test run before we run this fixture.
			//put the core in c:/temp for now since generated path is a bit too long
			try {
				if (Directory.Exists(@"c:\temp\"))
					Directory.CreateDirectory(@"c:\temp\");
				FileBasePath = Path.Combine(@"c:\temp\", "IntegrationTestCores");

				//FileBasePath = Path.Combine(context.TestRunDirectory, "IntegrationTestCores");
				if (Directory.Exists(FileBasePath))
					Directory.Delete(FileBasePath, true);
			} catch (Exception e) {
				Console.WriteLine(e);
			}

			//var newConfig = new OAuthPlugin.OAuthPluginConfig();
			newConfig.InitializeDefault();
			newConfig.validationOptions.ValidateAudience = false;
			newConfig.validationOptions.validateIssuer = false;
			newConfig.validationOptions.ValidateIssuerSigningKey = false;
			newConfig.validationOptions.ValidateLifetime = false;
			//this.discoveryUri = "https://demo.identityserver.io/.well-known/openid-configuration";
			//newConfig.issuer = "https://demo.identityserver.io";
			newConfig.issuer = "http://localhost:5000";
			newConfig.audiences = new string[] { "api" };
			newConfig.identity = new string[] { "sub", "client_id" };
			newConfig.requireHttpsDiscovery = false;
			//this by default gives everyone access. they just may not have permissions to do anything
			newConfig.defaultGroups = new[] { "nobody/nobody" };
			newConfig.systemAccessRequirements = new List<List<AuthRequirement>>() {
				new List<AuthRequirement>(){
						new AuthRequirement { key = "role", values = {"admin", "maplargeaccess"} },
				},
				new List<AuthRequirement>(){
						new AuthRequirement { key = "client_role", values = {"admin"} },
				},

				new List<AuthRequirement>(){
						new AuthRequirement { key = "division", values = {"northwest"} }
				}
			};
			newConfig.GroupMembershipRequirements = new Dictionary<string, List<List<AuthRequirement>>>() {
				{"SysAdmin/root", new List<List<AuthRequirement>>() {
					new List<AuthRequirement>() {
						new AuthRequirement() { key = "role", values = { "admin", "otherrole"} }
					}
				}},
				{"test/viewers", new List<List<AuthRequirement>>() {
					new List<AuthRequirement>() {
						new AuthRequirement() { key = "role", values = { "viewer", "otherviewerrole"} }
					}
				}},

			};
			_confFileName = Path.GetTempFileName();
			File.WriteAllText(_confFileName, JsonConvert.SerializeObject(newConfig));

			var opt = new Dictionary<string, string> {
				{
					"authPluginTypeName",
					"MapLarge.OAuthPlugin.OAuthPlugin, MapLarge.OAuthPlugin, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"
				},
				{"authPluginParams", "config=" + _confFileName},
				{
					"serverSyncAuthPluginTypeName",
					"MapLarge.OAuthPlugin.OAuthPlugin, MapLarge.OAuthPlugin, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"
				},
				{"serverSyncAuthPluginParams", "config=" + _confFileName}
			};
			//options.authPluginTypeName = 
			//options.authPluginParams =;

			_core = CreateACore("OAuth Plugin Test Core", opt);
		}

		[ClassCleanup]
		public static void TestFixtureTearDown() {
			ShutdownACore(_core);
			_core = null;

			if (File.Exists(_confFileName)) {
				File.Delete(_confFileName);
			}
		}

		[TestInitialize]
		public void TestInitialize() {
			Monitor.Enter(ForceSingleThreadedTestsLock);
		}

		[TestCleanup]
		public void TestCleanup() {
			Monitor.Exit(ForceSingleThreadedTestsLock);
		}

		public class Access_Token {
			public string access_token;
			public string token_type;
			public string expires_in;
		}

		static Dictionary<string, string> client_credentials = new Dictionary<string, string>{
				{ "grant_type" ,"client_credentials"},
				{ "scope" ,"api"},
				{ "client_id" ,"client"},
				{ "client_secret" ,"secret"}
			};


		[TestMethod]
		public void TestClientCredentials() {


			MockHttpRequest request = GetBearerToken(client_credentials);
			var result = _core.Auth.ProcessLogin(request, new MockHttpResponse(), 3600);

			Assert.IsTrue(result.success);
		}

		static Dictionary<string, string> passworFlow = new Dictionary<string, string>{
				{ "grant_type" ,"password"},
				{ "scope" ,"api email profile openid"},
				{ "client_id" ,"ro.client"},
				{ "client_secret" ,"secret"},
				{ "username" ,"bob"},
				{ "password" ,"bob"}
			};

		static Dictionary<string, string> noacessPassworFlow = new Dictionary<string, string>{
				{ "grant_type" ,"password"},
				{ "scope" ,"api email profile openid"},
				{ "client_id" ,"ro.client"},
				{ "client_secret" ,"secret"},
				{ "username" ,"noaccess"},
				{ "password" ,"noaccess"}
			};
		[TestMethod]
		public void TestPasswordHasNoAccess() {

			MockHttpRequest request = GetBearerToken(noacessPassworFlow);

			var result = _core.Auth.ProcessLogin(request, new MockHttpResponse(), 3600);

			Assert.IsFalse(result.success);
		}


		[TestMethod]
		public void TestPassword() {

			MockHttpRequest request = GetBearerToken(passworFlow);

			var result = _core.Auth.ProcessLogin(request, new MockHttpResponse(), 3600);

			Assert.IsTrue(result.success);
		}

		private static MockHttpRequest GetBearerToken(Dictionary<string, string> postData) {
			//get an access_token to test with ex:

			//{
			//"access_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6IjcyOThjZjAyMDA2MWU4MDIzYzE1NjM3ZTc3NzNjZGE2IiwidHlwIjoiSldUIn0.eyJuYmYiOjE1MjM5MDMxMjcsImV4cCI6MTUyMzkwNjcyNywiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo1MDAwIiwiYXVkIjpbImh0dHA6Ly9sb2NhbGhvc3Q6NTAwMC9yZXNvdXJjZXMiLCJhcGkxIl0sImNsaWVudF9pZCI6InJvLmNsaWVudCIsInN1YiI6IjEiLCJhdXRoX3RpbWUiOjE1MjM5MDMxMjcsImlkcCI6ImxvY2FsIiwic2NvcGUiOlsiYXBpMSJdLCJhbXIiOlsicHdkIl19.Gv9SI2nBy0_qoZ-VAUVO0Xa0qxhXLTSsb4jTn1AXUvJYb3xBme6OCQgJu3i8yZh4LMsVzTn1HJZUQYdFgw2dXuLrPr_KrOblU7DzOyhXWEGM4UawVng518FwOWd9raN-NbE1GzYUiEzjX6v-ZyVbgpypvTepGpmk8c4gNM-6N9KoeAcnchoxHmvJSMS-MgYPeJ-hJRGUVkIdc1l5eAAhU3vyrBjK9ydk2FRhk_Bg1SlExvIKcKxDcv1I1pc7pc1eyFCb7DBnA7lDbdK4_Sjre94jNDLjaTqtD6KIbHH1eOGCk_DgOMCUsn-nKIZeVtce5OJ0opVKucokGxUX9ft6fA",
			//	"expires_in":3600,
			//	"token_type":"Bearer"
			//}

			var issuer = new Uri(newConfig.issuer);
			//possible discovery config
			var tokenUri = new Uri(issuer, "connect/token");

			HttpClient client = new HttpClient();

			var content = new FormUrlEncodedContent(postData);
			
			var response = client.PostAsync(tokenUri, content).GetAwaiter().GetResult();
			if (!response.IsSuccessStatusCode)
				throw new Exception($"status: {response.StatusCode} {response.ReasonPhrase}");
			var responseString = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
			var token = JsonConvert.DeserializeObject<Access_Token>(responseString);

			//'Authorization: Bearer ACCESS_TOKEN'
			var request = new MockHttpRequest(new Dictionary<string, string> {
				{ "Authorization", $"{token.token_type} {token.access_token}"}
			});
			return request;
		}

		public static Core CreateACore(string coreName, Dictionary<string, string> opts = null, Dictionary<string, string> replopts = null, bool omitRootPass = false) {
			if (opts == null) {
				opts = new Dictionary<string, string> { { "geocoder", "false" } };

				if (!omitRootPass) {
					opts.Add("root_pass", "integrationPass");
				}
			} else {
				if (!opts.ContainsKey("geocoder")) {
					opts.Add("geocoder", "false");
				}

				if (!omitRootPass && !opts.ContainsKey("root_pass")) {
					{
						opts.Add("root_pass", "integrationPass");
					}
				}
			}

			var coreDirectory = Path.Combine(FileBasePath, coreName);
			var newCore = new Core(Path.Combine(coreDirectory, "TestMLDB") + Path.DirectorySeparatorChar, coreName, opts, replopts);

			return newCore;
		}

		public static void ShutdownACore(Core core) {
			if (core == null) {
				return;
			}

			Console.WriteLine($"Shutting down core: {core.CoreName}");

			core.IsShuttingDown = true;

			// wait for threads to stop.
			DateTime startWaiting = DateTime.UtcNow;
			while (CurrentActivitiesManager.currentThreads.Any(t => t.Value.IsAlive)
				   && DateTime.UtcNow - startWaiting < TimeSpan.FromSeconds(30)) {
				Thread.Sleep(1000);
			}

			core.ReleaseLock();
		}



		public class MockHttpResponse : HttpResponseBase { }
		public class MockHttpRequest : HttpRequestBase {
			private NameValueCollection mockHeaders;
			private NameValueCollection mockParams;
			private NameValueCollection mockForms = new NameValueCollection();
			private HttpCookieCollection mockCookies = new HttpCookieCollection();
			private MemoryStream inputStream;
			public override NameValueCollection Headers
			{
				get
				{
					return mockHeaders;
				}
			}
			public override string UserHostAddress
			{
				get
				{
					return "127.0.0.1";
				}
			}
			public override Uri Url
			{
				get
				{
					return new Uri("http://ml.loc/auth/login");
				}
			}

			public override string this[string key]
			{
				get
				{
					return mockParams[key];
				}
			}

			public override NameValueCollection Params
			{
				get
				{
					return mockParams;
				}
			}

			public override Stream InputStream
			{
				get
				{
					return inputStream;
				}
			}

			public override
				WindowsIdentity LogonUserIdentity
			{
				get
				{
					return base.LogonUserIdentity;
				}
			}

			public MockHttpRequest(Dictionary<string, string> headers = null, Dictionary<string, string> parameters = null, string content = "") {
				mockHeaders = new NameValueCollection();
				mockParams = new NameValueCollection();
				inputStream = new MemoryStream(Encoding.UTF8.GetBytes(content ?? ""));
				if (headers != null) {
					foreach (var kvp in headers) {
						mockHeaders[kvp.Key] = kvp.Value;
					}
				}

				if (parameters != null) {
					foreach (var kvp in parameters) {
						mockParams[kvp.Key] = kvp.Value;
					}
				}
			}

			public override NameValueCollection Form
			{
				get { return mockForms; }
			}

			public override HttpCookieCollection Cookies
			{
				get { return mockCookies; }
			}

		}
	}
}
