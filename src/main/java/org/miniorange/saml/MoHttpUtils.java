package org.miniorange.saml;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.impl.conn.SystemDefaultRoutePlanner;
import org.apache.http.util.EntityUtils;
import javax.net.ssl.SSLContext;
import java.net.ProxySelector;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.logging.Logger;

public class MoHttpUtils {

	private static final Logger LOGGER = Logger.getLogger(MoHttpUtils.class.getName());

	public static final String CONTENT_TYPE_JSON = "application/json";

	public static String sendPostRequest(String url, String data, String contentType, HashMap headers) {
		try {
			LOGGER.fine("MoHttpUtils sendPostRequest Sending POST request to " + url + " with payload " + data);
			CloseableHttpClient httpClient = getHttpClient();
			HttpPost postRequest = new HttpPost(url);

			if (headers != null) {
				Iterator iterator = headers.entrySet().iterator();
				if (!headers.isEmpty()) {
					while (iterator.hasNext()) {
						Map.Entry pairs = (Map.Entry) iterator.next();
						postRequest.setHeader(pairs.getKey().toString(), pairs.getValue().toString());
					}
				}
			}
			StringEntity input = new StringEntity(data);

			input.setContentType(contentType);
			postRequest.setEntity(input);

			HttpResponse response = httpClient.execute(postRequest);
			LOGGER.fine("Response for HTTP Request: " + response.toString() + " and Status Code: " + response
					.getStatusLine().getStatusCode());

			if (response.getEntity() != null) {
				LOGGER.fine("Response Entity found. Reading Response payload.");
				String status = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
				LOGGER.fine("Response payload: " + status);
				httpClient.close();
				return status;
			} else {
				LOGGER.fine("Response Entity NOT found. Returning EMPTY string.");
				httpClient.close();
				return StringUtils.EMPTY;
			}

		} catch (Exception e) {
			LOGGER.fine("An exception occured while sending post request :"+e.getMessage());
			throw new MoPluginException(MoPluginException.PluginErrorCode.UNKNOWN, e.getMessage(), e);
		}
	}
	private static CloseableHttpClient getHttpClient() throws KeyStoreException, NoSuchAlgorithmException,
			KeyManagementException {
		HttpClientBuilder builder = HttpClientBuilder.create();
		SSLContext sslContext = new SSLContextBuilder().loadTrustMaterial(null, (arg0, arg1) -> true).build();
		SSLConnectionSocketFactory sslConnectionFactory = new SSLConnectionSocketFactory(sslContext,
				SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
		builder.setSSLSocketFactory(sslConnectionFactory);

		Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
				.register("https", sslConnectionFactory)
				.register("http", PlainConnectionSocketFactory.INSTANCE)
				.build();

		HttpClientConnectionManager ccm = new BasicHttpClientConnectionManager(registry);

		builder.setConnectionManager(ccm);

		//return builder.build();
		SystemDefaultRoutePlanner routePlanner = new SystemDefaultRoutePlanner(ProxySelector.getDefault());
		CloseableHttpClient httpclient = HttpClients.custom().setRoutePlanner(routePlanner).setConnectionManager(ccm)
				.build();
		return httpclient;
	}

	public static String sendGetRequest(String url, HashMap headers) {
		try {
			LOGGER.fine("MoHttpUtils sendPostRequest Sending POST request to " + url);
			CloseableHttpClient httpClient =getHttpClient();
			HttpGet getRequest = new HttpGet(url);

			if (headers != null) {
				Iterator iterator = headers.entrySet().iterator();
				if (!headers.isEmpty()) {
					while (iterator.hasNext()) {
						Map.Entry pairs = (Map.Entry) iterator.next();
						getRequest.setHeader(pairs.getKey().toString(), pairs.getValue().toString());
					}
				}
			}

			HttpResponse response = httpClient.execute(getRequest);
			LOGGER.fine("Response for HTTP Request: " + response.toString() + " and Status Code: " + response
					.getStatusLine().getStatusCode());
			//return "true";

			if (response.getEntity() != null) {
				LOGGER.fine("Response Entity found. Reading Response payload.");
				String status = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
				LOGGER.fine("Response payload: " + status);
				httpClient.close();
				return status;
			} else {
				LOGGER.fine("Response Entity NOT found. Returning EMPTY string.");
				httpClient.close();
				return StringUtils.EMPTY;
			}

		} catch (Exception e) {
			LOGGER.fine("An exception occured while sending post request :"+e.getMessage());
			throw new MoPluginException(MoPluginException.PluginErrorCode.UNKNOWN, e.getMessage(), e);
		}
	}
	public static HashMap<String, String> getAuthorizationHeaders(Long customerId, String apiKey) {
		LOGGER.fine("in getAuthorizationHeaders ");
		LOGGER.fine(customerId+"ssss:"+apiKey);
		HashMap<String, String> headers = new HashMap<String, String>();
		Long timestamp = System.currentTimeMillis();
		String stringToHash = customerId + timestamp + apiKey;
		String hashValue = DigestUtils.sha512Hex(stringToHash);

		headers.put("Customer-Key", String.valueOf(customerId));
		headers.put("Timestamp", String.valueOf(timestamp));
		headers.put("Authorization", hashValue);
		LOGGER.fine("Headers"+headers);
		return headers;
	}
}
