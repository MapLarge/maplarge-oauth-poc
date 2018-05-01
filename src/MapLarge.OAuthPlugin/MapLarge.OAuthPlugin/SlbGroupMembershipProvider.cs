using MapLarge.Engine.Unified.Auth;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using static MapLarge.OAuthPlugin.OAuthPlugin;

namespace MapLarge.OAuthPlugin {
	public class SlbGroupMembershipProvider : IGroupMembershipProvider {
		private GroupProviderConfig _config;
		private bool _isInitialized = false;

		/// <summary>
		/// Queries the SLB entitlement endpoint for group membership given a valid access_token
		/// </summary>
		/// <param name="access_token">the encoded access_token issued </param>
		/// <returns>return a string array of group names that this user/access token is a member of</returns>
		public string[] GetGroupMemberships(string access_token) {
			if (!_isInitialized)
				throw new Exception("The group membership provider has not been properly initialized!");

			// todo: pass in original user name header, not maplarge email address
			// will make a difference for uses with special characters in the name (like a .)
			if (string.IsNullOrWhiteSpace(access_token))
				throw new ArgumentException("The access_token cannot be blank or null", nameof(access_token));


			//Query params key:APIkey
			HttpClient httpClient = HttpClientManager.Instance.HttpClient;
			var requestMessage = new HttpRequestMessage(HttpMethod.Get, $"{_config.entitlementEndpoint}?apikey={_config.apiKey}");
			requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access_token);
			//slb-account-id:tenant1
			requestMessage.Headers.Add("slb-account-id", _config.tenentId);

			
			var response = httpClient.SendAsync(requestMessage).GetAwaiter().GetResult();
			if (response.IsSuccessStatusCode) {
				var content = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
				var usergroups= JsonConvert.DeserializeObject<EntitlementResponse>(content);
				//process the group response here.
				//for this example use return the name property
				return usergroups.groups.Select(g => g.name).ToArray();
			}
			else
				throw new Exception($"The Slb entitlement service returned an error: {response.StatusCode} {response.ReasonPhrase}");
		}

		public void Initialize(string configFilePath) {
			string cfgTxt = File.ReadAllText(configFilePath);
			_config = JsonConvert.DeserializeObject<GroupProviderConfig>(cfgTxt);
			if (string.IsNullOrWhiteSpace(_config.entitlementEndpoint))
				throw new Exception("Missing group membership URL!");
			if (string.IsNullOrWhiteSpace(_config.apiKey))
				throw new Exception("Missing Api Key!");
			if (string.IsNullOrWhiteSpace(_config.tenentId))
				throw new Exception("Missing tententId!");
			_isInitialized = true;
		}
	}

	public class GroupProviderConfig: OAuthPluginConfig {
		public string entitlementEndpoint;
		public string apiKey;
		public string tenentId;
	}

	public class EntitlementResponse {
		public class EntitlementGroup {
			public string name;
			public string email;
			public string description;
		}

		public EntitlementGroup[] groups;
		public string memberEmail;
	}
}


