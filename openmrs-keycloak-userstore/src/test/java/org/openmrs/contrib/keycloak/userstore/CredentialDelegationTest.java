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

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;

import org.junit.After;
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

/**
 * OpenMRS decides whether a password is right, and this provider believes it only about the user it
 * asked about.
 */
@RunWith(MockitoJUnitRunner.class)
public class CredentialDelegationTest extends JPAHibernateTest {

	@Mock
	private KeycloakSession session;

	@Mock
	private ComponentModel model;

	@Mock
	private RealmModel realm;

	private StubOpenmrs openmrs;

	private OpenmrsAuthenticator authenticator;

	@Before
	public void startOpenmrs() throws IOException {
		openmrs = new StubOpenmrs();
		authenticator = new OpenmrsAuthenticator(session, model, new UserDao(em),
		        new OpenmrsSessionClient(openmrs.baseUrl()));
	}

	@After
	public void stopOpenmrs() {
		openmrs.stop();
	}

	@Test
	public void offersTheResolvedUsersOwnNameAndThePasswordTyped() {
		openmrs.authenticates("uuid-user-200");

		authenticates("SidVaish", "whatever-was-typed");

		assertThat(openmrs.credentialsOffered(), equalTo("SidVaish:whatever-was-typed"));
	}

	@Test
	public void offersTheSystemIdForAUserOpenmrsIdentifiesThatWay() {
		openmrs.authenticates("uuid-user-99");

		authenticates("99-1", "Sys123");

		assertThat(openmrs.credentialsOffered(), equalTo("99-1:Sys123"));
	}

	@Test
	public void authenticatesWhenOpenmrsSaysSo() {
		openmrs.authenticates("uuid-user-200");

		assertTrue(authenticates("SidVaish", "whatever-openmrs-accepts"));
	}

	@Test
	public void refusesWhenOpenmrsRefuses() {
		openmrs.refusesEverybody();

		assertFalse(authenticates("SidVaish", "Sid123"));
	}

	@Test
	public void refusesWhenOpenmrsAuthenticatesADifferentUser() {
		openmrs.authenticates("uuid-user-401");

		assertFalse(authenticates("collide", "Four001"));
	}

	@Test
	public void doesNotFollowARedirectCarryingThePassword() throws Exception {
		StubOpenmrs elsewhere = new StubOpenmrs();
		elsewhere.authenticates("uuid-user-200");
		try {
			openmrs.authenticates("uuid-user-200");
			openmrs.redirectsTo(elsewhere.baseUrl() + "/ws/rest/v1/session");

			assertFalse(authenticates("SidVaish", "Sid123"));
			assertThat("the password must not be re-sent to whatever Location names", elsewhere.credentialsOffered(),
			    equalTo(null));
		}
		finally {
			elsewhere.stop();
		}
	}

	@Test
	public void refusesWhenOpenmrsCannotBeReached() {
		openmrs.stop();

		assertFalse(authenticates("SidVaish", "Sid123"));
	}

	@Test
	public void doesNotCarryASessionCookieBetweenValidations() {
		openmrs.honoursASessionCookieFor("uuid-user-200");

		authenticates("SidVaish", "Sid123");
		boolean second = authenticates("SidVaish", "the-wrong-password");

		assertFalse("a JSESSIONID carried over makes OpenMRS answer true to any password", second);
		assertThat(openmrs.lastCookie(), equalTo(null));
	}

	@Test
	public void refusesAnEmptyPasswordWithoutAskingOpenmrs() {
		openmrs.authenticates("uuid-user-200");

		assertFalse(authenticates("SidVaish", ""));
		assertThat(openmrs.calls(), equalTo(0));
	}

	@Test
	public void refusesAPasswordCarryingAColonWithoutAskingOpenmrs() {
		openmrs.authenticates("uuid-user-200");

		for (String typed : new String[] { "Sid123:anything-at-all", ":Sid123" }) {
			assertFalse("OpenMRS reads a password only as far as its first colon, so it would take any suffix",
			    authenticates("SidVaish", typed));
		}
		assertThat(openmrs.calls(), equalTo(0));
	}

	@Test
	public void readsTheUsersOwnUuidRatherThanTheNestedPersons() {
		openmrs.authenticatesSomebodyElseButNestsThePerson("uuid-user-401", "uuid-user-200");

		assertFalse(authenticates("SidVaish", "Sid123"));
	}

	@Test
	public void refusesARetiredUserWithoutAskingOpenmrs() {
		openmrs.authenticates("uuid-user-252");

		assertFalse(authenticates("retired-nurse", "Retired1"));
		assertThat(openmrs.calls(), equalTo(0));
	}

	@Test
	public void refusesACredentialThatIsNotAPasswordWithoutAskingOpenmrs() {
		openmrs.authenticates("uuid-user-200");
		UserModel user = authenticator.getUserByUsername(realm, "SidVaish");

		assertFalse(authenticator.isValid(realm, user, new UserCredentialModel(null, OTPCredentialModel.TYPE, "Sid123")));
		assertThat(openmrs.calls(), equalTo(0));
	}

	@Test
	public void refusesWhenOpenmrsRefusesButStillNamesTheUser() {
		openmrs.refusesButStillNames("uuid-user-200");

		assertFalse(authenticates("SidVaish", "Sid123"));
	}

	@Test
	public void refusesWhenOpenmrsAnswersAnErrorStatus() {
		openmrs.authenticates("uuid-user-200");
		openmrs.answersStatus(500);

		assertFalse(authenticates("SidVaish", "Sid123"));
	}

	@Test
	public void refusesABaseUrlWithNoScheme() {
		assertThat(OpenmrsSessionClient.problemWith("gateway/openmrs"), containsString("http://"));
		assertThat(new OpenmrsSessionClient("gateway/openmrs").authenticate("SidVaish", "Sid123").isPresent(),
		    equalTo(false));
	}

	@Test
	public void saysSoWhenNoOpenmrsBaseUrlIsConfigured() {
		for (String unset : new String[] { null, "", "   " }) {
			assertThat(OpenmrsSessionClient.problemWith(unset), containsString("No OpenMRS base URL"));
			assertThat(new OpenmrsSessionClient(unset).authenticate("SidVaish", "Sid123").isPresent(), equalTo(false));
		}
	}

	@Test
	public void toleratesATrailingSlashOnTheBaseUrl() {
		openmrs.authenticates("uuid-user-200");
		OpenmrsSessionClient client = new OpenmrsSessionClient(openmrs.baseUrl() + "/");

		assertThat(client.authenticate("SidVaish", "Sid123").orElse(null), equalTo("uuid-user-200"));
	}

	@Test
	public void refusesAnIdThatDoesNotIdentifyAnOpenmrsUser() {
		openmrs.authenticates("uuid-user-200");
		UserModel notOurs = mock(UserModel.class);
		when(notOurs.getId()).thenReturn("f:openmrs:not-a-number");

		assertFalse(
		    authenticator.isValid(realm, notOurs, new UserCredentialModel(null, PasswordCredentialModel.TYPE, "anything")));
		assertThat(openmrs.calls(), equalTo(0));
	}

	@Test
	public void findsNoUserThatDoesNotExist() {
		assertThat(authenticator.getUserByUsername(realm, "nobody-at-all"), nullValue());
	}

	@Test
	public void reportsARetiredUserAsDisabled() {
		assertFalse(authenticator.getUserByUsername(realm, "retired-nurse").isEnabled());
		assertTrue(authenticator.getUserByUsername(realm, "SidVaish").isEnabled());
	}

	@Test
	public void handsTheOpenmrsSessionBackAfterEveryCheck() throws Exception {
		openmrs.authenticates("uuid-user-200");
		authenticates("SidVaish", "Sid123");
		openmrs.refusesEverybody();
		authenticates("SidVaish", "the-wrong-one");

		for (int waited = 0; waited < 50 && openmrs.released().size() < 2; waited++) {
			Thread.sleep(20);
		}

		assertThat("a refused check opens a session too, so both must come back", openmrs.released().size(), equalTo(2));
		assertThat(openmrs.released().get(0), containsString("JSESSIONID=STUBSESSION"));
	}

	private boolean authenticates(String username, String password) {
		UserModel user = authenticator.getUserByUsername(realm, username);
		assertThat("the fixture must contain " + username, user, notNullValue());
		return authenticator.isValid(realm, user, new UserCredentialModel(null, PasswordCredentialModel.TYPE, password));
	}
}
