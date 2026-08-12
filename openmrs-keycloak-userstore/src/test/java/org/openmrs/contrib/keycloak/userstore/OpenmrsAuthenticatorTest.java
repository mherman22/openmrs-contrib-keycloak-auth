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

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.openmrs.contrib.keycloak.userstore.data.UserDao;
import org.openmrs.contrib.keycloak.userstore.models.OpenmrsUserModel;
import org.openmrs.contrib.keycloak.userstore.provider.OpenmrsAuthenticator;

@RunWith(MockitoJUnitRunner.class)
public class OpenmrsAuthenticatorTest extends JPAHibernateTest {

	@Mock
	private KeycloakSession session;

	@Mock
	private ComponentModel model;

	@Mock
	private UserDao userDao;

	@Mock
	private RealmModel realmModel;

	private OpenmrsUserModel openmrsUserModel;

	private OpenmrsAuthenticator openmrsAuthenticator;

	@Before
	public void setup() {
		openmrsAuthenticator = new OpenmrsAuthenticator(session, model, userDao);

		openmrsUserModel = new OpenmrsUserModel();
		openmrsUserModel.setUsername("admin");
	}

	@Test
	public void getUserByUsername() {
		when(userDao.getOpenmrsUserByUsername("admin")).thenReturn(openmrsUserModel);

		UserModel result = openmrsAuthenticator.getUserByUsername(realmModel, "admin");

		assertThat(result, notNullValue());
		assertThat(result.getUsername(), notNullValue());
		assertThat(result.getUsername(), equalTo("admin"));
	}

	/**
	 * Keycloak's federation contract is that a lookup for a user who does not exist answers null. These
	 * three used to wrap the lookup unconditionally, so a missing user became a UserAdapter around
	 * nothing; and the query beneath them threw NoResultException, which Keycloak reported to the
	 * browser as "Unexpected error when handling authentication request to identity provider". Every
	 * mistyped username at the login form produced that page instead of "Invalid username or password".
	 */
	@Test
	public void getUserByUsernameReturnsNullWhenThereIsNoSuchUser() {
		when(userDao.getOpenmrsUserByUsername("nobody")).thenReturn(null);

		assertThat(openmrsAuthenticator.getUserByUsername(realmModel, "nobody"), nullValue());
	}

	@Test
	public void getUserByEmailReturnsNullWhenThereIsNoSuchUser() {
		when(userDao.getOpenmrsUserByEmail("nobody@example.org")).thenReturn(null);

		assertThat(openmrsAuthenticator.getUserByEmail(realmModel, "nobody@example.org"), nullValue());
	}

	@Test
	public void getUserByIdReturnsNullWhenThereIsNoSuchUser() {
		when(userDao.getOpenmrsUserByUserId(404)).thenReturn(null);

		assertThat(openmrsAuthenticator.getUserById(realmModel, "f:00000000-0000-0000-0000-000000000000:404"), nullValue());
	}

	/**
	 * A user with no credential row is a failed sign-in, not a server fault. The array was dereferenced
	 * unconditionally, so this was a NullPointerException out of the credential check.
	 */
	@Test
	public void aUserWithNoCredentialRowSimplyFailsToAuthenticate() {
		UserModel userModel = openmrsAuthenticator.getUserByUsername(realmModel, "admin");
		when(userDao.getUserPasswordAndSaltOnRecord(userModel)).thenReturn(null);

		assertFalse(openmrsAuthenticator.isValid(realmModel, userModel, new org.keycloak.models.UserCredentialModel(null,
		        org.keycloak.models.credential.PasswordCredentialModel.TYPE, "whatever")));
	}
}
