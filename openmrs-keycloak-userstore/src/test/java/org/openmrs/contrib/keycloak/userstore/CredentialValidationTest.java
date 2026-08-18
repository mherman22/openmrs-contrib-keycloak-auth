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

/**
 * The credential path end to end -- real users, real hashes, real queries -- because that is what
 * decides who gets into every application behind this realm. Weighted towards what must not
 * authenticate: the tests that matter are the ones that would let someone in.
 */
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

	// What must authenticate.

	@Test
	public void authenticatesAgainstTheSha512HashOpenmrsWritesToday() {
		assertTrue(authenticates("SidVaish", "Sid123"));
	}

	/**
	 * OpenMRS's Security.hashMatches still accepts SHA-1, so a database upgraded from an older OpenMRS
	 * holds users whose password is a SHA-1 hash and who sign in to OpenMRS every day. Checking only
	 * SHA-512 locked all of them out of Keycloak, and told them their password was wrong.
	 */
	@Test
	public void authenticatesAgainstALegacySha1Hash() {
		assertTrue(authenticates("legacy-sha1", "Legacy1"));
	}

	/** And the same digest as written by the hex routine that dropped leading zeros. */
	@Test
	public void authenticatesAgainstAHashTheHistoricHexRoutineWrote() {
		assertTrue(authenticates("legacy-oldhex", "Ancient1"));
	}

	/** OpenMRS stores its admin account with no username at all. */
	@Test
	public void authenticatesTheUserOpenmrsIdentifiesBySystemId() {
		assertTrue(authenticates("99-1", "Sys123"));
	}

	// What must not.

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

	/** A password with no salt: OpenMRS never writes one, and cannot authenticate one either. */
	@Test
	public void refusesAUserWhosePasswordHasNoSalt() {
		assertFalse(authenticates("no-salt", "Sid123"));
	}

	@Test
	public void refusesTheWrongPasswordForTheUserIdentifiedBySystemId() {
		assertFalse(authenticates("99-1", "Sys124"));
	}

	/** The stored hash is not a password, however much it looks like one to whoever read the column. */
	@Test
	public void refusesTheStoredHashOfferedAsThePassword() {
		assertFalse(authenticates("SidVaish",
		    "0dd4de366d0ee9c2cad07be099cdb954d8f60f8eedd4a968fa624e51bc8022ebb85e914bf39846a5dcbc9d89fd8b86a7143a1698136df05cf1ce3dc595df0321"));
	}

	/** Only passwords are checked here. Anything else is not this provider's to answer. */
	@Test
	public void refusesACredentialThatIsNotAPassword() {
		UserModel user = authenticator.getUserByUsername(realm, "SidVaish");

		assertFalse(authenticator.isValid(realm, user, new UserCredentialModel(null, OTPCredentialModel.TYPE, "Sid123")));
	}

	/**
	 * A Keycloak id that does not carry an OpenMRS user_id. Nothing should be read for it, and nothing
	 * should throw either.
	 */
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

	/**
	 * A user who has never had a password set: both columns are null. This was a NullPointerException
	 * out of the credential check, which Keycloak reported to the browser as a server error rather than
	 * as a failed sign-in.
	 */
	@Test
	public void refusesAUserWhoHasNoPasswordOnRecord() {
		assertFalse(authenticates("admin", "anything"));
		assertFalse(authenticates("admin", ""));
	}

	/**
	 * The password is right. The user has been retired in OpenMRS, which is what an administrator does
	 * when someone leaves, and OpenMRS's own authenticate will not look at a retired user at all. This
	 * provider read nothing of the sort, so retiring a user revoked their OpenMRS access and left them
	 * signing in to every application behind this realm.
	 */
	@Test
	public void refusesARetiredUserWithTheRightPassword() {
		assertFalse(authenticates("retired-nurse", "Retired1"));
	}

	/** And Keycloak is told, so its own checks and its admin console agree. */
	@Test
	public void reportsARetiredUserAsDisabled() {
		assertFalse(authenticator.getUserByUsername(realm, "retired-nurse").isEnabled());
		assertTrue(authenticator.getUserByUsername(realm, "SidVaish").isEnabled());
	}

	/**
	 * OpenMRS locks an account after seven failed sign-ins and keeps it locked for
	 * security.unlockAccountWaitingTime minutes. Keycloak read none of that, so an account OpenMRS had
	 * locked went on authenticating here with the right password -- and, since this provider does not
	 * write to OpenMRS, failures at the Keycloak form never counted towards that lock either.
	 */
	@Test
	public void refusesTheRightPasswordWhileOpenmrsHasTheAccountLockedOut() {
		lockedOutAt(System.currentTimeMillis());

		assertFalse(authenticates("locked-out", "Locked1"));
	}

	/** The waiting time comes from OpenMRS's own global property: ten minutes in this fixture. */
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

	/** How OpenMRS records an account that is not locked. */
	@Test
	public void treatsAZeroTimestampAsNotLockedOut() {
		lockedOut("0");

		assertTrue(authenticates("locked-out", "Locked1"));
	}

	/** An unreadable timestamp must not lock everyone out, which is also what OpenMRS does with one. */
	@Test
	public void treatsAnUnreadableTimestampAsNotLockedOut() {
		lockedOut("not a timestamp");

		assertTrue(authenticates("locked-out", "Locked1"));
	}

	/** With no global property set, OpenMRS's own default of five minutes applies. */
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

	/** Nothing OpenMRS wrote, so nothing can match it. */
	@Test
	public void refusesAPasswordHashInAFormatNoOpenmrsVersionWrites() {
		assertFalse(authenticates("odd-hash", "anything"));
	}

	/**
	 * User 400's username is user 401's system_id. Whichever of them the lookup resolves, the password
	 * checked has to be that user's own: the credential used to be fetched by matching the name again,
	 * in a separate unordered query, so the other user's password could have been the one that let this
	 * session in.
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
