using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace MapLarge.OAuthPlugin {
	public sealed class HttpClientManager {
		private static volatile HttpClientManager instance;
		private static object syncRoot = new Object();

		private HttpClientManager() { }
		public Func<HttpClient> HttpClientFactory = () => new HttpClient();
		private HttpClient httpClient;

		public HttpClient HttpClient {
			get {
				if (httpClient == null)
					lock (syncRoot) {
						if (httpClient == null)
							httpClient = HttpClientFactory();
					}
				return httpClient;
			}
		}
		public static HttpClientManager Instance
		{
			get
			{
				if (instance == null) {
					lock (syncRoot) {
						if (instance == null)
							instance = new HttpClientManager();
					}
				}

				return instance;
			}
		}
	}
}
