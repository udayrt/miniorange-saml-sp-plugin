package org.miniorange.saml;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.routing.HttpRoutePlanner;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.impl.conn.SystemDefaultRoutePlanner;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.ProxySelector;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

public class MoHttpUtils {

	private static final Logger LOGGER = Logger.getLogger(MoHttpUtils.class.getName());

	public static CloseableHttpClient getHttpClient() throws KeyStoreException, NoSuchAlgorithmException,
			KeyManagementException {
		HttpClientBuilder builder = HttpClientBuilder.create();

		SSLContext sslContext = SSLContexts.custom().build();

		SSLConnectionSocketFactory sslConnectionFactory = new SSLConnectionSocketFactory(sslContext,
				SSLConnectionSocketFactory.getDefaultHostnameVerifier());
		builder.setSSLSocketFactory(sslConnectionFactory);

		Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
				.register("https", sslConnectionFactory)
				.register("http", PlainConnectionSocketFactory.INSTANCE)
				.build();

		HttpClientConnectionManager ccm = new BasicHttpClientConnectionManager(registry);

		builder.setConnectionManager(ccm);

		HttpRoutePlanner routePlanner = new SystemDefaultRoutePlanner(ProxySelector.getDefault());
		builder.setRoutePlanner(routePlanner);

		CloseableHttpClient httpclient = builder.build();
		return httpclient;
	}

	public static String sendGetRequest(String url, HashMap<String, String> headers) throws IOException {
		LOGGER.info("MoHttpUtils sendGetRequest Sending GET request to " + url);
		try (CloseableHttpClient httpClient = getHttpClient()) {
			LOGGER.fine("MoHttpUtils sendGetRequest Sending GET request to " + url);

			HttpGet getRequest = new HttpGet(url);

			if (headers != null) {
				for (Map.Entry<String, String> entry : headers.entrySet()) {
					getRequest.setHeader(entry.getKey(), entry.getValue());
				}
			}

			try (CloseableHttpResponse response = httpClient.execute(getRequest)) {
				int statusCode = response.getStatusLine().getStatusCode();
				LOGGER.fine("Response for HTTP Request: " + response.toString() + " and Status Code: " + statusCode);

				if (statusCode == HttpStatus.SC_OK && response.getEntity() != null) {
					LOGGER.fine("Response Entity found. Reading Response payload.");
					String payload = EntityUtils.toString(response.getEntity());
					LOGGER.fine("Response payload: " + payload);
					return payload;
				} else {
					LOGGER.fine("Response Entity NOT found or Status Code is not OK. Returning EMPTY string.");
					return StringUtils.EMPTY;
				}
			} catch (ClientProtocolException e) {
				return StringUtils.EMPTY;
			}
		} catch (IOException e) {
			LOGGER.fine("An exception occurred while sending get request: " + e.getMessage());
			return StringUtils.EMPTY;
		} catch (KeyStoreException | NoSuchAlgorithmException | KeyManagementException e) {
			return StringUtils.EMPTY;
		}
	}
}
