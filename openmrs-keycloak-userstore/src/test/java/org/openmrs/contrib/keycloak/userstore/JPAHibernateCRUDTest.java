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
import static org.mockito.Mockito.when;

import java.util.List;

import com.google.common.collect.ImmutableMap;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.models.UserModel;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.openmrs.contrib.keycloak.userstore.data.UserDao;
import org.openmrs.contrib.keycloak.userstore.models.OpenmrsUserModel;

@RunWith(MockitoJUnitRunner.class)
public class JPAHibernateCRUDTest extends JPAHibernateTest {

	private UserDao userDao;

	@Mock
	private UserModel userModel;

	@Before
	public void setup() {
		userDao = new UserDao(em);
	}

	@Test
	public void getUserByUsername() {
		OpenmrsUserModel query = userDao.getOpenmrsUserByUsername("admin");
		assertThat(query.getUsername(), equalTo("admin"));
		assertThat(query.getUserId(), equalTo(152));
	}

	@Test
	public void getUserById() {
		assertThat(userDao.getOpenmrsUserByUserId(186).getUsername(), equalTo("Sid"));
	}

	@Test
	public void getPasswordAndSalt() {
		when(userModel.getUsername()).thenReturn("SidVaish");

		String[] result = userDao.getUserPasswordAndSaltOnRecord(userModel);

		assertThat(result[0], equalTo("Sid123"));
		assertThat(result[1], equalTo("123"));
	}

	@Test
	public void getUserCount() {
		assertThat(userDao.getOpenmrsUserCount(), equalTo(4));
	}

	@Test
	public void searchUsers() {
		List<OpenmrsUserModel> query = userDao
		        .searchForOpenmrsUserQuery(ImmutableMap.<String, String> builder().put("username", "admin").build(), 0, 1);
		assertThat(query.get(0).getUserId(), equalTo(152));
	}

	/**
	 * OpenMRS stores its admin account with no username, identified by system_id, and any user created
	 * without a username the same way. Matching only on username left every such user unable to
	 * authenticate through Keycloak, whatever password they typed. OpenMRS's own getUserByUsername
	 * matches either column, which is why signing in to OpenMRS directly always worked for them.
	 */
	@Test
	public void findsAUserThatHasOnlyASystemId() {
		OpenmrsUserModel user = userDao.getOpenmrsUserByUsername("99-1");

		assertThat(user, notNullValue());
		assertThat(user.getUserId(), equalTo(99));
		assertThat(user.getUsername(), nullValue());
		assertThat(user.getSystemId(), equalTo("99-1"));
	}

	@Test
	public void readsTheCredentialOfAUserThatHasOnlyASystemId() {
		when(userModel.getUsername()).thenReturn("99-1");

		String[] result = userDao.getUserPasswordAndSaltOnRecord(userModel);

		assertThat(result, notNullValue());
		assertThat(result[0], equalTo("Sys123"));
		assertThat(result[1], equalTo("999"));
	}

	/** A name that matches neither column is simply absent, rather than an exception. */
	@Test
	public void answersNullForAUserThatDoesNotExist() {
		assertThat(userDao.getOpenmrsUserByUsername("nobody-at-all"), nullValue());
	}

	/**
	 * A search for one user must not answer with another. The criteria used to be combined with or, so
	 * every clause for a criterion that was not supplied made the whole query true and the search
	 * returned the entire table; the original assertion passed only because the user it wanted happened
	 * to have the lowest id.
	 */
	@Test
	public void searchDoesNotReturnUsersThatDoNotMatch() {
		List<OpenmrsUserModel> found = userDao
		        .searchForOpenmrsUserQuery(ImmutableMap.<String, String> builder().put("username", "Sid").build(), 0, 10);

		assertThat(found.size(), equalTo(1));
		assertThat(found.get(0).getUsername(), equalTo("Sid"));
	}

	@Test
	public void searchForAUsernameNobodyHasFindsNobody() {
		assertThat(userDao.searchForOpenmrsUserQuery(
		    ImmutableMap.<String, String> builder().put("username", "nobody-at-all").build(), 0, 10).size(), equalTo(0));
	}
}
