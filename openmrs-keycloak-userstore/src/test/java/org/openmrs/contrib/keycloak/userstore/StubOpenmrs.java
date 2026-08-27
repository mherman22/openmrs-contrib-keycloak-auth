/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.contrib.keycloak.userstore;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import com.sun.net.httpserver.HttpServer;

/**
 * An OpenMRS that answers what a test tells it to and records what it was asked, so a test can pin
 * the request as well as the response.
 */
public class StubOpenmrs {

	private final HttpServer server;

	private String authenticatedUuid;

	private String lastAuthorization;

	private String lastCookie;

	private int calls;

	private boolean honourSessionCookie;

	private boolean personFirst;

	private int status = 200;

	private boolean namesAUserWhenRefusing;

	private String refusedUuid;

	private String cookieUuid;

	private String redirectTo;

	private String personUuid = "uuid-of-the-person-not-the-user";

	public StubOpenmrs() throws IOException {
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/openmrs/ws/rest/v1/session", exchange -> {
			calls++;
			lastAuthorization = exchange.getRequestHeaders().getFirst("Authorization");
			List<String> cookies = exchange.getRequestHeaders().get("Cookie");
			lastCookie = cookies == null || cookies.isEmpty() ? null : cookies.get(0);

			boolean signedIn = authenticatedUuid != null
			        || (honourSessionCookie && lastCookie != null && lastCookie.contains("JSESSIONID"));
			String uuid = authenticatedUuid != null ? authenticatedUuid : cookieUuid;
			String body = signedIn ? "{\"authenticated\":true,\"user\":{" + userObject(uuid) + "}}"
			        : "{\"authenticated\":false"
			                + (namesAUserWhenRefusing ? ",\"user\":{" + userObject(refusedUuid) + "}" : "") + "}";

			if (redirectTo != null) {
				exchange.getResponseHeaders().add("Location", redirectTo);
				exchange.sendResponseHeaders(302, -1);
				exchange.close();
				return;
			}

			byte[] payload = body.getBytes(StandardCharsets.UTF_8);
			exchange.getResponseHeaders().add("Content-Type", "application/json");
			exchange.getResponseHeaders().add("Set-Cookie", "JSESSIONID=STUBSESSION; Path=/openmrs; HttpOnly");
			exchange.sendResponseHeaders(status, payload.length);
			try (OutputStream out = exchange.getResponseBody()) {
				out.write(payload);
			}
		});
		server.start();
	}

	/** Answers authenticated:true, naming this user, for any credential offered. */
	public void authenticates(String uuid) {
		this.authenticatedUuid = uuid;
	}

	/** Answers authenticated:false however good the password is, as OpenMRS does for a locked user. */
	public void refusesEverybody() {
		this.authenticatedUuid = null;
	}

	/**
	 * Answers authenticated:true to any request carrying a JSESSIONID, as the real OpenMRS does: the
	 * field reports the state of the session, not the credentials on the request.
	 */
	public void honoursASessionCookieFor(String uuid) {
		this.honourSessionCookie = true;
		this.cookieUuid = uuid;
		this.authenticatedUuid = null;
	}

	public String baseUrl() {
		return "http://127.0.0.1:" + server.getAddress().getPort() + "/openmrs";
	}

	public int calls() {
		return calls;
	}

	public String lastCookie() {
		return lastCookie;
	}

	/** @return the credentials the provider actually sent, as "identifier:password". */
	public String credentialsOffered() {
		if (lastAuthorization == null || !lastAuthorization.startsWith("Basic ")) {
			return null;
		}

		return new String(Base64.getDecoder().decode(lastAuthorization.substring("Basic ".length())),
		        StandardCharsets.UTF_8);
	}

	/**
	 * Answers with a user whose own uuid is somebody else's, while the person nested inside it carries
	 * the uuid the caller is looking for. Anything that takes a uuid from the response without
	 * insisting on the user's own reads the person's and authenticates the wrong user.
	 */
	public void authenticatesSomebodyElseButNestsThePerson(String otherUuid, String personUuid) {
		this.authenticatedUuid = otherUuid;
		this.personUuid = personUuid;
		this.personFirst = true;
	}

	private String userObject(String uuid) {
		String person = "\"person\":{\"uuid\":\"" + personUuid + "\"}";
		String own = "\"uuid\":\"" + uuid + "\"";
		return personFirst ? person + "," + own : own + "," + person;
	}

	/** As OpenMRS does for a locked account: refuses, while still naming the user in the response. */
	public void refusesButStillNames(String uuid) {
		this.authenticatedUuid = null;
		this.namesAUserWhenRefusing = true;
		this.refusedUuid = uuid;
	}

	/** Sends the caller somewhere else, as a proxy or a login page would. */
	public void redirectsTo(String location) {
		this.redirectTo = location;
	}

	/**
	 * A status other than 200, with the body left intact: a proxy or an error page can carry something
	 * that parses, and the status is what says it did not come from OpenMRS.
	 */
	public void answersStatus(int status) {
		this.status = status;
	}

	public void stop() {
		server.stop(0);
	}
}
