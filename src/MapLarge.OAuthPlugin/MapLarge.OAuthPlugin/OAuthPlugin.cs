using MapLarge.Engine.Unified;
using MapLarge.Engine.Unified.Auth;
using MapLarge.Permission.DataStore;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace MapLarge.OAuthPlugin {

	public class OAuthPlugin : AbsExternalAuthPlugin<OAuthPlugin.OAuthPluginConfig> {


		public override string Name
		{
			get { return nameof(OAuthPlugin); }
		}

		public override string FileName
		{
			//the name of the configuration file that will be loaded.
			get { return "oAuth.json"; }
		}

		protected override void ValidateConfig() {
			// validate the configuration
			if (_config == null)
				throw new Exception("OAuth config invalid: mapping is missing");


			if (string.IsNullOrWhiteSpace(_config.identity))
				throw new Exception("OAuth config invalid: identity header is not specified");

			//if (!_config.autoCreateAccount.enabled && (_config.defaultGroups == null || _config.defaultGroups.Length == 0))
			//	throw new Exception("OAuth  config invalid: define defaultGroups or enable Account auto creation");
		}

		protected override void ReadConfigurationFromParameters(Dictionary<string, string> parameters) {

		}
		public override AuthPluginBehavior GetPluginBehavior() {
			if (!_isInitialized)
				throw new Exception("The OAuth auth plugin is not initialized!");

			return new AuthPluginBehavior { alwaysCallLogin = true, showSplashScreenOnFailure = _config.showSplashScreenOnFailure, canLogIn = false, forceLoginOnWMSRequest = true, canLogOut = _config.allowLogOut };
		}


		public override Dictionary<string, string> GetPluginConfigOptions() {
			var ret = new Dictionary<string, string>();
			return ret;
		}

		/// <summary>
		/// ProcessLogin is responsibile for taking information from a request and ensureing that there is a maplarge user available
		/// with the correct permissions.For OAuth it expects a Bearer token that is then used to gernerate user + permissions.
		///In the maplarge API pipeline ProcessLogin only gets called by Auth/Login api.
		/// </summary>
		/// <param name="request">an http request that contains an Authorization Bearer token</param>
		/// <param name="response">not used by this plugin</param>
		/// <param name="expiration">lifetime for any maplarge generated token </param>
		/// <returns>returns authorization info with user and a MapLarge token that can be used for api calls.</returns>
		public override AuthResult ProcessLogin(HttpRequestBase request, HttpResponseBase response, int expiration) {
			
			if (!_isInitialized)
				throw new Exception("The OAuth auth plugin is not initialized!");


			// collect the actual header values
			var actualHeaderValues = new Dictionary<string, string[]>();


			//get the Authorization header
			string key = "Authorization";
			string headerVal = request.Headers[key];
			if (string.IsNullOrWhiteSpace(headerVal))
				return FailedAuth($"{key} header is not present", request);

			//get the access token.
			var headerPieces = headerVal.Split(' ');
			if (headerPieces.Length != 2)
				return FailedAuth($"{key} header does not contain type and token.", request);

			if (string.Compare(headerPieces[0], "Bearer", true) != 0)
				return FailedAuth($"Token type is not a Bearer token. Actual:{headerPieces[0]}", request);

			var accesstoken = headerPieces[1];

			//validate the token
			var userContext = ValidateToken(accesstoken).GetAwaiter().GetResult();

			//look at the claims get user claim based off the identity key specified in config
			string userName = userContext.Claims.FirstOrDefault(c => c.Type == _config.identity)?.Value;


			string lowerUserName = userName.ToLower().Trim();
			var groupToMlGroupMapping = new Dictionary<string, string[]>();
			var groupsAllowedAccess = new Dictionary<string, string[]>();

			//here the claims would be retrieved from the token
			//those claims would then be mapped to maplarge groups. 
			//get the groups from the claims by the configured role claim type
			//if role claim not set all claims are used
			
			string[] usersGroups = string.IsNullOrWhiteSpace(_config.roleClaimType)
				?userContext.Claims.Select(c => c.Value).ToArray()
				: userContext.Claims.Where(c => c.Type == _config.roleClaimType).Select(c => c.Value).ToArray();

			//setup to resolve through AuthRequirements configuration
			groupToMlGroupMapping[GROUP_MEMBERSHIP_KEY] = usersGroups;
			groupsAllowedAccess[ALLOWED_ACCESS_KEY] = usersGroups;

			//are there any claims that are configured for access? if not reject user.
			if (!CheckGroupMemberships(groupsAllowedAccess).Any())
				return FailedAuth("User is not approved for access.", request);




			//define the username in the MapLarge format
			var mlUsername = $"{lowerUserName}@{_config.userNameEmailDomain}";
			
			//builds an AuthResult given the user and claim to group mapping defined in GroupRequirements definition
			return BuildAuthResultFromUserAndGroups(mlUsername, groupToMlGroupMapping, _config.defaultGroups, request, expiration);
		}

		/// <summary>
		/// validates a jwtToken based off the options defined in config.
		/// </summary>
		/// <param name="token">the token</param>
		/// <returns>returns an instance of the validated token</returns>
		private async Task<JwtSecurityToken> ValidateToken(string token) {
			if (string.IsNullOrEmpty(token)) throw new ArgumentNullException(nameof(token));

			
			//issuer config
			var issuer = new Uri(_config.issuer);

			
			//be default make the discovery url the issuer + OAUTH spec https://tools.ietf.org/html/draft-ietf-oauth-discovery-07#section-3
			var discovery = new Uri(issuer, ".well-known/openid-configuration");

			//sometimes the issuer can be different than the discovery endpoint. allow for that
			//is the discovery url absolute?
			if (Uri.IsWellFormedUriString(_config.discoveryUri, UriKind.Absolute))
				discovery = new Uri(_config.discoveryUri);
			else if (Uri.IsWellFormedUriString(_config.discoveryUri, UriKind.Relative))
				discovery = new Uri(issuer, _config.discoveryUri);


			
			var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(discovery.AbsoluteUri,
				new OpenIdConnectConfigurationRetriever(),
				new HttpDocumentRetriever { RequireHttps = _config.requireHttpsDiscovery }); 

			//get the public keys from the discovery endpoint
			//this could be cached to avoid excessive lookup
			var discoveryDocument = await configurationManager.GetConfigurationAsync(default(CancellationToken)).ConfigureAwait(false);
			var signingKeys = discoveryDocument.SigningKeys;


			//these are other options for building a key to use to validate if the key is known.
			#region alternate keys
			//load from file
			//IssuerSigningKey = new X509SecurityKey(new X509Certificate2(certLocation)),

			///provided signing cert
			//	string X509Cert = "CERT CONTENTS";
			//X509Certificate2 DefaultCert_Public_2048 = new X509Certificate2(Convert.FromBase64String(X509Cert));
			//X509SecurityKey DefaultX509Key_Public_2048 = new X509SecurityKey(DefaultCert_Public_2048);
			//SigningCredentials DefaultX509SigningCreds_Public_2048_RsaSha2_Sha2 = new SigningCredentials(DefaultX509Key_Public_2048, SecurityAlgorithms.RsaSha256Signature);


			///Alternative asyematric public key build. Typeically gathered from discovery endpoint
			//var e = Base64Url.Decode("AQAB");
			//var n = Base64Url.Decode("wKchfRYocmVQW2tEbagQYLJDwkYOyU2Nf1vomzHZGdjeIyyvexLjW6YW6kCnNG5-I2Lm67pTUE8fBI7gL68whkUYsXCx7lXgo3Snx17_xwPBPdmiI42Xx-IAU-D8YvO7aOaYwbUqwiPrDG5GeaaMHqqbNu4G4vrKptkgBvUSSbNWfqmkg3e-BdrjLIlkyqMmpGuAokMl_eHH90_Av_D27Nw8RzhsGezlThQUte-MXd5oFLr4IT730SKRksR1Clm--CGIc7rr79oaVF1OZw44cgl1DsezsmKw9MQRTe8Mr_j4l0i6RPuVdm_LzUpE5zoStb1ta5b6RBekO1F5ZEjNUQ");

			//var signingKey = new RsaSecurityKey(new RSAParameters { Exponent = e, Modulus = n }) {
			//	KeyId = "2c4147d18d355afaf60bce38220898f2"
			//};

			#endregion

			var validationParameters = new TokenValidationParameters {
				ValidateIssuer = _config.validationOptions.validateIssuer,
				ValidIssuer = issuer.OriginalString,
				ValidateIssuerSigningKey = _config.validationOptions.ValidateIssuerSigningKey,
				IssuerSigningKeys = signingKeys,
				ValidateLifetime = _config.validationOptions.ValidateLifetime,
				ValidateAudience = _config.validationOptions.ValidateAudience,
				ValidAudiences = _config.audiences,
				// Allow for some drift in server time
				// (a lower value is better; we recommend five minutes or less)
				ClockSkew = TimeSpan.FromMinutes(5),

			};

			var principal = new JwtSecurityTokenHandler().ValidateToken(token, validationParameters, out var rawValidatedToken);
			JwtSecurityToken newToken =  (JwtSecurityToken)rawValidatedToken;
			//if there is a 'sub' claim on the token query for additional claims 
			if (principal.HasClaim(c => c.Type == "sub")) {
				//look up user information to gather additional claims
				
				HttpClient httpClient = new HttpClient();
				httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
				var response = await httpClient.GetAsync(discoveryDocument.UserInfoEndpoint).ConfigureAwait(false);
				if (response.IsSuccessStatusCode) {
					var content = await response.Content.ReadAsStringAsync();
					///from here take the additional claims and add to the returned token.

				} 

				
				
			}
			return newToken;

		}

		/// <summary>
		/// defines options for the OAuthPlugin
		/// </summary>
		public class OAuthPluginConfig : IAuthPluginConfig {

			//the uri of the full or partial discovery endpoint
			public string discoveryUri = null;
			//this allows discovery on non https discovery endoints
			public bool requireHttpsDiscovery = true;

			//the uri of the token issuer used for validating tokens and if not set building the discovery uri
			public string issuer = null;

			//list of accepted audiences used in validating tokens
			public string[] audiences = null;

			//the name of the claim that represents the username that will become the maplarge user
			public string identity = null;

			//controls what to validate when validating tokens
			public ValidationOptions validationOptions = new ValidationOptions();

			//the claimtype to use for roles/groups
			public string roleClaimType = null;

			//default groups all MapLarge users will have
			public string[] defaultGroups = null;
			
			//rules for mapping claims to MapLarge groups as well as access
			public Dictionary<string, List<List<AuthRequirement>>> GroupMembershipRequirements { get; set; }


			public bool showSplashScreenOnFailure = true;
			//user name format
			public string userNameEmailDomain = "ml.oauth";
			public bool allowLogOut = false;

			public class ValidationOptions {
				public bool validateIssuer = true;
				public bool ValidateIssuerSigningKey = true;
				public bool ValidateLifetime = true;
				public bool ValidateAudience = true;
			}

			public void InitializeDefault() {
				this.defaultGroups = new string[] { "nobody/nobody" };
				this.validationOptions = new ValidationOptions();
			}
		}


	}

}
