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

import java.util.concurrent.TimeUnit;

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
		authenticator = new OpenmrsAuthenticator(session, model, new UserDao(em));
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
	public void authenticatesAgainstTheSha512HashOpenmrsWritesToday() {
		assertTrue(authenticates("SidVaish", "Sid123"));
	}

	/**
	 * OpenMRS's Security.hashMatches still accepts SHA-1, so a database upgraded from an older OpenMRS
	 * holds users who sign in with a SHA-1 password every day.
	 */
	@Test
	public void authenticatesAgainstALegacySha1Hash() {
		assertTrue(authenticates("legacy-sha1", "Legacy1"));
	}

	@Test
	public void authenticatesAgainstAHashTheHistoricHexRoutineWrote() {
		assertTrue(authenticates("legacy-oldhex", "Ancient1"));
	}

	@Test
	public void authenticatesTheUserOpenmrsIdentifiesBySystemId() {
		assertTrue(authenticates("99-1", "Sys123"));
	}

	@Test
	public void refusesTheWrongPassword() {
		assertFalse(authenticates("SidVaish", "Sid124"));
	}

	@Test
	public void refusesTheWrongPasswordAgainstALegacyHash() {
		assertFalse(authenticates("legacy-sha1", "Legacy2"));
		assertFalse(authenticates("legacy-oldhex", "Ancient2"));
	}

	@Test
	public void refusesTheRightPasswordWithoutTheSalt() {
		assertFalse(authenticates("SidVaish", "Sid123123"));
	}

	@Test
	public void refusesAnEmptyPassword() {
		assertFalse(authenticates("SidVaish", ""));
	}

	@Test
	public void refusesAUserWhosePasswordHasNoSalt() {
		assertFalse(authenticates("no-salt", "Sid123"));
	}

	@Test
	public void refusesTheWrongPasswordForTheUserIdentifiedBySystemId() {
		assertFalse(authenticates("99-1", "Sys124"));
	}

	@Test
	public void refusesTheStoredHashOfferedAsThePassword() {
		assertFalse(authenticates("SidVaish",
		    "0dd4de366d0ee9c2cad07be099cdb954d8f60f8eedd4a968fa624e51bc8022ebb85e914bf39846a5dcbc9d89fd8b86a7143a1698136df05cf1ce3dc595df0321"));
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
	public void refusesAUserWhoHasNoPasswordOnRecord() {
		assertFalse(authenticates("admin", "anything"));
		assertFalse(authenticates("admin", ""));
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

	@Test
	public void refusesTheRightPasswordWhileOpenmrsHasTheAccountLockedOut() {
		lockedOutAt(System.currentTimeMillis());

		assertFalse(authenticates("locked-out", "Locked1"));
	}

	/** The waiting time is OpenMRS's own global property, set to ten minutes in this fixture. */
	@Test
	public void keepsTheAccountLockedForAsLongAsOpenmrsWould() {
		lockedOutAt(System.currentTimeMillis() - TimeUnit.MINUTES.toMillis(6));

		assertFalse(authenticates("locked-out", "Locked1"));
	}

	@Test
	public void authenticatesOnceTheOpenmrsLockoutHasRunOut() {
		lockedOutAt(System.currentTimeMillis() - TimeUnit.MINUTES.toMillis(11));

		assertTrue(authenticates("locked-out", "Locked1"));
	}

	@Test
	public void treatsAZeroTimestampAsNotLockedOut() {
		lockedOut("0");

		assertTrue(authenticates("locked-out", "Locked1"));
	}

	@Test
	public void treatsAnUnreadableTimestampAsNotLockedOut() {
		lockedOut("not a timestamp");

		assertTrue(authenticates("locked-out", "Locked1"));
	}

	@Test
	public void fallsBackToTheOpenmrsDefaultWaitingTime() {
		lockedOutAt(System.currentTimeMillis() - TimeUnit.MINUTES.toMillis(6));
		unlockWaitingTime(null);
		try {
			assertTrue(authenticates("locked-out", "Locked1"));
		}
		finally {
			unlockWaitingTime("10");
		}
	}

	private void lockedOutAt(long timestamp) {
		lockedOut(String.valueOf(timestamp));
	}

	private void lockedOut(String propertyValue) {
		inTransaction(
		    "update user_property set property_value = :value " + "where user_id = 253 and property = 'lockoutTimestamp'",
		    propertyValue);
	}

	private void unlockWaitingTime(String minutes) {
		inTransaction(
		    "update global_property set property_value = :value " + "where property = 'security.unlockAccountWaitingTime'",
		    minutes);
	}

	private void inTransaction(String statement, String value) {
		em.getTransaction().begin();
		em.createNativeQuery(statement).setParameter("value", value).executeUpdate();
		em.getTransaction().commit();
		em.clear();
	}

	@Test
	public void refusesAPasswordHashInAFormatNoOpenmrsVersionWrites() {
		assertFalse(authenticates("odd-hash", "anything"));
	}

	/**
	 * User 400's username is user 401's system_id. Whichever the lookup resolves, the password checked
	 * has to be that user's own.
	 */
	@Test
	public void checksTheCredentialOfTheUserThatWasResolved() {
		UserModel four00 = authenticator.getUserById(realm, "f:openmrs:400");
		UserModel four01 = authenticator.getUserById(realm, "f:openmrs:401");

		assertTrue(authenticator.isValid(realm, four00, credential("Four001")));
		assertTrue(authenticator.isValid(realm, four01, credential("Four011")));

		assertFalse(authenticator.isValid(realm, four00, credential("Four011")));
		assertFalse(authenticator.isValid(realm, four01, credential("Four001")));
	}
}
