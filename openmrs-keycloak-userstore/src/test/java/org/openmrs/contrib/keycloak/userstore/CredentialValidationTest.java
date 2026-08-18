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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
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
