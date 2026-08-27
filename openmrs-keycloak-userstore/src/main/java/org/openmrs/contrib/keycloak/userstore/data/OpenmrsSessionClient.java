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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Asks OpenMRS whether a password is right, so that OpenMRS's own authentication scheme decides it
 * rather than this provider comparing hashes itself.
 */
public class OpenmrsSessionClient {

	private static final Logger log = LoggerFactory.getLogger(OpenmrsSessionClient.class);

	private static final Pattern AUTHENTICATED = Pattern.compile("\"authenticated\"\\s*:\\s*(true|false)");

	private static final Pattern USER_UUID = Pattern.compile("\"user\"\\s*:\\s*\\{.*?\"uuid\"\\s*:\\s*\"([^\"]+)\"",
	    Pattern.DOTALL);

	private final URI sessionUri;

	private final HttpClient httpClient;

	public OpenmrsSessionClient(String baseUrl) {
		this.sessionUri = URI.create(baseUrl.replaceAll("/+$", "") + "/ws/rest/v1/session");
		/*
		 * No cookie handler, and java.net.http does not fall back to CookieHandler.getDefault(). A
		 * JSESSIONID from an earlier call makes OpenMRS answer authenticated:true to any password at
		 * all, so a client that kept one would accept every password.
		 */
		this.httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10))
		        .followRedirects(HttpClient.Redirect.NEVER).build();
	}

	/**
	 * @return the uuid of the user OpenMRS authenticated, or empty if it authenticated nobody. The
	 *         caller must check that uuid against the user it resolved: a name can match one user's
	 *         username and another's system_id, and OpenMRS answers for whichever it resolves.
	 */
	public Optional<String> authenticate(String identifier, String password) {
		if (identifier == null || identifier.isEmpty() || password == null || password.isEmpty()) {
			return Optional.empty();
		}

		String credentials = Base64.getEncoder()
		        .encodeToString((identifier + ":" + password).getBytes(StandardCharsets.UTF_8));
		HttpRequest request = HttpRequest.newBuilder(sessionUri).GET().timeout(Duration.ofSeconds(15))
		        .header("Authorization", "Basic " + credentials).header("Accept", "application/json").build();

		HttpResponse<String> response;
		try {
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
			log.warn("OpenMRS answered {} when asked to check a credential", response.statusCode());
			return Optional.empty();
		}

		/*
		 * OpenMRS answers 200 with authenticated:false for a wrong password and for a user that does
		 * not exist, so the status code says nothing about whether anyone signed in.
		 */
		Matcher authenticated = AUTHENTICATED.matcher(response.body());
		if (!authenticated.find() || !"true".equals(authenticated.group(1))) {
			return Optional.empty();
		}

		Matcher uuid = USER_UUID.matcher(response.body());
		if (!uuid.find()) {
			log.warn("OpenMRS reported an authenticated session without naming the user");
			return Optional.empty();
		}

		return Optional.of(uuid.group(1));
	}
}
