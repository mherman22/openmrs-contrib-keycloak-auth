/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.contrib.keycloak.userstore.data;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Asks OpenMRS whether a password is right, so that the authentication scheme the deployment has
 * configured decides it.
 */
public class OpenmrsSessionClient {

	private static final Logger log = LoggerFactory.getLogger(OpenmrsSessionClient.class);

	private static final ObjectMapper JSON = new ObjectMapper();

	private final URI sessionUri;

	private final String problem;

	private final HttpClient httpClient;

	public OpenmrsSessionClient(String baseUrl) {
		this.problem = problemWith(baseUrl);
		this.sessionUri = problem == null ? URI.create(baseUrl.trim().replaceAll("/+$", "") + "/ws/rest/v1/session") : null;
		/*
		 * No cookie handler, and java.net.http does not consult CookieHandler.getDefault(). OpenMRS
		 * answers authenticated:true to any request carrying a JSESSIONID it already signed in, so a
		 * client that kept one would accept every password.
		 */
		this.httpClient = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(5))
		        .followRedirects(HttpClient.Redirect.NEVER).build();
	}

	/**
	 * @return why this base URL cannot be used to reach OpenMRS, or null if it can. A caller saving
	 *         configuration can report it; the constructor accepts it either way, so that a realm
	 *         imported without one still starts.
	 */
	public static String problemWith(String baseUrl) {
		if (baseUrl == null || baseUrl.trim().isEmpty()) {
			return "No OpenMRS base URL is configured, so no credential can be checked.";
		}

		URI uri;
		try {
			uri = URI.create(baseUrl.trim());
		}
		catch (IllegalArgumentException e) {
			return "The OpenMRS base URL is not a URL: '" + baseUrl + "'";
		}

		if (!"http".equalsIgnoreCase(uri.getScheme()) && !"https".equalsIgnoreCase(uri.getScheme())) {
			return "The OpenMRS base URL must begin with http:// or https://, but is '" + baseUrl + "'";
		}

		if (uri.getHost() == null) {
			return "The OpenMRS base URL names no host: '" + baseUrl + "'";
		}

		return null;
	}

	/**
	 * @return the uuid of the user OpenMRS authenticated, or empty if it authenticated nobody. The
	 *         caller must check that uuid against the user it resolved: a name can be one user's
	 *         username and another's system_id, and OpenMRS answers for whichever it resolves.
	 */
	public Optional<String> authenticate(String identifier, String password) {
		if (problem != null) {
			log.error("Cannot check the credential of '{}': {}", identifier, problem);
			return Optional.empty();
		}

		if (identifier == null || identifier.isEmpty() || password == null || password.isEmpty()) {
			return Optional.empty();
		}

		/*
		 * OpenMRS's REST authorization filter splits the decoded header on every ':' and reads the
		 * password from the second field alone, so it would compare only the text before the first
		 * colon: it refuses a password that contains one, and accepts the right password followed by
		 * ':' and anything. Refusing here keeps that second case out and spends no OpenMRS login
		 * attempt on the first, which would count towards the account lockout.
		 */
		if (password.indexOf(':') >= 0) {
			log.warn("Refusing the credential of '{}' without asking OpenMRS: OpenMRS reads a password over REST only "
			        + "as far as its first ':', so a password containing one cannot be checked this way",
			    identifier);
			return Optional.empty();
		}

		HttpResponse<String> response;
		try {
			String credentials = Base64.getEncoder()
			        .encodeToString((identifier + ":" + password).getBytes(StandardCharsets.UTF_8));
			HttpRequest request = HttpRequest.newBuilder(sessionUri).GET().timeout(Duration.ofSeconds(5))
			        .header("Authorization", "Basic " + credentials).header("Accept", "application/json").build();
			response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			log.error("Interrupted while asking OpenMRS at {} to check a credential", sessionUri);
			return Optional.empty();
		}
		catch (Exception e) {
			log.error("Could not reach OpenMRS at {} to check a credential", sessionUri, e);
			return Optional.empty();
		}

		if (response.statusCode() != 200) {
			log.warn("OpenMRS at {} answered {} when asked to check a credential", sessionUri, response.statusCode());
			return Optional.empty();
		}

		JsonNode body;
		try {
			body = JSON.readTree(response.body());
		}
		catch (Exception e) {
			log.error("Could not read the session response from OpenMRS at {}", sessionUri, e);
			return Optional.empty();
		}

		/*
		 * OpenMRS answers 200 with authenticated:false for a wrong password and for a user that does
		 * not exist, so the status says nothing about whether anyone signed in.
		 */
		if (!body.path("authenticated").asBoolean(false)) {
			return Optional.empty();
		}

		// The user's own uuid, not the person nested inside it, which is a different object.
		String uuid = body.path("user").path("uuid").asText(null);
		if (uuid == null || uuid.isEmpty()) {
			log.warn("OpenMRS reported an authenticated session without naming the user");
			return Optional.empty();
		}

		return Optional.of(uuid);
	}
}
