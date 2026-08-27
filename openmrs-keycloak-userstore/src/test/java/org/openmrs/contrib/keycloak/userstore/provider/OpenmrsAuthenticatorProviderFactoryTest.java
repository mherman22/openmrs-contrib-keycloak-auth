/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.contrib.keycloak.userstore.provider;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.openmrs.contrib.keycloak.userstore.StubOpenmrs;

/**
 * The factory decides which OpenMRS a component's passwords are sent to, and which base URL stops a
 * component being saved.
 */
public class OpenmrsAuthenticatorProviderFactoryTest {

	private final OpenmrsAuthenticatorProviderFactory factory = new OpenmrsAuthenticatorProviderFactory();

	@Test
	public void sendsEachComponentsPasswordsToItsOwnOpenmrs() throws Exception {
		StubOpenmrs first = new StubOpenmrs();
		StubOpenmrs second = new StubOpenmrs();
		try {
			first.authenticates("uuid-first");
			second.authenticates("uuid-second");

			factory.sessionClientFor(componentWith(first.baseUrl())).authenticate("nurse", "First123");
			factory.sessionClientFor(componentWith(second.baseUrl())).authenticate("nurse", "Second123");

			assertThat(first.credentialsOffered(), equalTo("nurse:First123"));
			assertThat("the second component's password must not go to the first component's OpenMRS",
			    second.credentialsOffered(), equalTo("nurse:Second123"));
		}
		finally {
			first.stop();
			second.stop();
		}
	}

	@Test
	public void keepsOneClientPerBaseUrl() {
		assertThat(factory.sessionClientFor(componentWith("http://gateway/openmrs")),
		    sameInstance(factory.sessionClientFor(componentWith("http://gateway/openmrs"))));
	}

	@Test
	public void buildsAClientForAComponentCarryingNoBaseUrl() {
		assertThat(factory.sessionClientFor(componentWith(null)), notNullValue());
	}

	@Test
	public void refusesToSaveAComponentWhoseBaseUrlIsMalformed() {
		try {
			factory.validateConfiguration(null, null, componentWith("gateway/openmrs"));
			fail("a base URL that names no scheme cannot reach OpenMRS and must be refused at save");
		}
		catch (ComponentValidationException e) {
			// The reason, not the type: null session and realm would raise this exception anyway.
			assertThat(e.getMessage(), containsString("must begin with http://"));
		}
	}

	@Test
	public void acceptsARealmCarryingNoBaseUrl() {
		for (String unset : new String[] { null, "", "   " }) {
			OpenmrsAuthenticatorProviderFactory.validateBaseUrl(unset);
		}
	}

	@Test
	public void acceptsABaseUrlThatCanReachOpenmrs() {
		OpenmrsAuthenticatorProviderFactory.validateBaseUrl("http://gateway/openmrs");
	}

	private ComponentModel componentWith(String baseUrl) {
		ComponentModel config = new ComponentModel();
		if (baseUrl != null) {
			config.put(OpenmrsAuthenticatorProviderFactory.OPENMRS_BASE_URL, baseUrl);
		}

		return config;
	}
}
