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

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.openmrs.contrib.keycloak.userstore.data.OpenmrsSessionClient;
import org.openmrs.contrib.keycloak.userstore.data.UserDao;
import org.openmrs.contrib.keycloak.userstore.provider.OpenmrsAuthenticator;

@RunWith(MockitoJUnitRunner.class)
public class CredentialValidationTest extends JPAHibernateTest {

	@Mock
	private KeycloakSession session;

	@Mock
	private ComponentModel model;

	@Mock
	private RealmModel realm;

	private OpenmrsAuthenticator authenticator;

	@Before
	public void setup() {
		authenticator = new OpenmrsAuthenticator(session, model, new UserDao(em),
		        new OpenmrsSessionClient("http://127.0.0.1:1"));
	}

	private boolean authenticates(String username, String password) {
		UserModel user = authenticator.getUserByUsername(realm, username);
		assertThat("the fixture must contain " + username, user, notNullValue());
		return authenticator.isValid(realm, user, credential(password));
	}

	private UserCredentialModel credential(String password) {
		return new UserCredentialModel(null, PasswordCredentialModel.TYPE, password);
	}

	@Test
	public void refusesACredentialThatIsNotAPassword() {
		UserModel user = authenticator.getUserByUsername(realm, "SidVaish");

		assertFalse(authenticator.isValid(realm, user, new UserCredentialModel(null, OTPCredentialModel.TYPE, "Sid123")));
	}

	@Test
	public void refusesAnIdThatDoesNotIdentifyAnOpenmrsUser() {
		UserModel notOurs = mock(UserModel.class);
		when(notOurs.getId()).thenReturn("f:openmrs:not-a-number");

		assertFalse(authenticator.isValid(realm, notOurs, credential("anything")));
	}

	@Test
	public void refusesAUserThatDoesNotExist() {
		assertThat(authenticator.getUserByUsername(realm, "nobody-at-all"), nullValue());
	}

	@Test
	public void refusesARetiredUserWithTheRightPassword() {
		assertFalse(authenticates("retired-nurse", "Retired1"));
	}

	@Test
	public void reportsARetiredUserAsDisabled() {
		assertFalse(authenticator.getUserByUsername(realm, "retired-nurse").isEnabled());
		assertTrue(authenticator.getUserByUsername(realm, "SidVaish").isEnabled());
	}

}
