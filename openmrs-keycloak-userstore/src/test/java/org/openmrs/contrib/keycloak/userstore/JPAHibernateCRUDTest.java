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

import java.util.List;

import com.google.common.collect.ImmutableMap;
import org.junit.Before;
import org.junit.Test;
import org.openmrs.contrib.keycloak.userstore.data.UserDao;
import org.openmrs.contrib.keycloak.userstore.models.OpenmrsUserModel;

public class JPAHibernateCRUDTest extends JPAHibernateTest {

	private UserDao userDao;

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
		String[] result = userDao.getUserPasswordAndSaltOnRecord(200);

		assertThat(result[0], equalTo(
		    "0dd4de366d0ee9c2cad07be099cdb954d8f60f8eedd4a968fa624e51bc8022ebb85e914bf39846a5dcbc9d89fd8b86a7143a1698136df05cf1ce3dc595df0321"));
		assertThat(result[1], equalTo("123"));
	}

	@Test
	public void readsAUserThatHasNoPasswordWithoutThrowing() {
		String[] result = userDao.getUserPasswordAndSaltOnRecord(152);

		assertThat(result, notNullValue());
		assertThat(result[0], nullValue());
		assertThat(result[1], nullValue());
	}

	@Test
	public void answersNullForTheCredentialOfARetiredUser() {
		assertThat(userDao.getUserPasswordAndSaltOnRecord(252), nullValue());
	}

	/**
	 * A retired user is still found, so an administrator can see the account they retired in the
	 * Keycloak console and in a user search. They are refused at the credential check instead.
	 */
	@Test
	public void stillFindsARetiredUser() {
		OpenmrsUserModel retired = userDao.getOpenmrsUserByUsername("retired-nurse");

		assertThat(retired, notNullValue());
		assertThat(retired.getRetired(), equalTo(true));
	}

	@Test
	public void answersNullForTheCredentialOfAUserThatDoesNotExist() {
		assertThat(userDao.getUserPasswordAndSaltOnRecord(4040), nullValue());
	}

	/**
	 * User 400's username is user 401's system_id. The credential read has to belong to the user that
	 * was asked for.
	 */
	@Test
	public void readsTheCredentialOfTheUserItIsAskedFor() {
		assertThat(userDao.getUserPasswordAndSaltOnRecord(400)[1], equalTo("c4"));
		assertThat(userDao.getUserPasswordAndSaltOnRecord(401)[1], equalTo("c5"));
	}

	@Test
	public void getUserCount() {
		assertThat(userDao.getOpenmrsUserCount(), equalTo(12));
	}

	@Test
	public void searchUsers() {
		List<OpenmrsUserModel> query = userDao
		        .searchForOpenmrsUserQuery(ImmutableMap.<String, String> builder().put("username", "admin").build(), 0, 1);
		assertThat(query.get(0).getUserId(), equalTo(152));
	}

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
		String[] result = userDao.getUserPasswordAndSaltOnRecord(99);

		assertThat(result, notNullValue());
		assertThat(result[0], equalTo(
		    "710cfad9cfcbd4b00d0bce89d9d812c904e307f9e34eb157e43e28e5de3f8f46007561b1fc8de0da85bdd2d4a770a5099076972ffe559bde3d7176aeb90a01a0"));
		assertThat(result[1], equalTo("999"));
	}

	@Test
	public void answersNullForAUserThatDoesNotExist() {
		assertThat(userDao.getOpenmrsUserByUsername("nobody-at-all"), nullValue());
	}

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
