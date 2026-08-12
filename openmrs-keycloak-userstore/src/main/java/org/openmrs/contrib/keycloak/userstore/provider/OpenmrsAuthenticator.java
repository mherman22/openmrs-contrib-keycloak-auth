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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.stream.Stream;

import jakarta.persistence.PersistenceException;
import lombok.AccessLevel;
import lombok.Setter;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.openmrs.contrib.keycloak.userstore.data.UserAdapter;
import org.openmrs.contrib.keycloak.userstore.data.UserDao;
import org.openmrs.contrib.keycloak.userstore.models.OpenmrsUserModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Setter(AccessLevel.PACKAGE)
public class OpenmrsAuthenticator implements CredentialInputValidator, UserLookupProvider, UserStorageProvider, UserQueryProvider {

	protected static final MessageDigest MESSAGE_DIGEST;

	private static final Logger log = LoggerFactory.getLogger(OpenmrsAuthenticator.class);

	static {
		try {
			MESSAGE_DIGEST = MessageDigest.getInstance("SHA-512");
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	protected KeycloakSession session;

	protected ComponentModel model;

	protected UserDao userDao;

	public OpenmrsAuthenticator(KeycloakSession session, ComponentModel model, UserDao userDao) {
		this.session = session;
		this.model = model;
		this.userDao = userDao;
	}

	// Keycloak's contract for all three: null when there is no such user. Wrapping the lookup
	// unconditionally produced a UserAdapter around nothing, which fails later and further away.

	@Override
	public UserModel getUserById(RealmModel realmModel, String id) {
		return adapt(realmModel, userDao.getOpenmrsUserByUserId(Integer.parseInt(StorageId.externalId(id))));
	}

	@Override
	public UserModel getUserByUsername(RealmModel realmModel, String username) {
		return adapt(realmModel, userDao.getOpenmrsUserByUsername(username));
	}

	@Override
	public UserModel getUserByEmail(RealmModel realmModel, String email) {
		return adapt(realmModel, userDao.getOpenmrsUserByEmail(email));
	}

	private UserModel adapt(RealmModel realmModel, OpenmrsUserModel user) {
		return user == null ? null : new UserAdapter(session, realmModel, model, user);
	}

	@Override
	public boolean supportsCredentialType(String credentialType) {
		return credentialType.equals(PasswordCredentialModel.TYPE);
	}

	@Override
	public boolean isConfiguredFor(RealmModel realmModel, UserModel userModel, String credentialType) {
		return credentialType.equals(PasswordCredentialModel.TYPE);
	}

	@Override
	public boolean isValid(RealmModel realmModel, UserModel userModel, CredentialInput credentialInput) {
		if (!(credentialInput instanceof UserCredentialModel) || !supportsCredentialType(credentialInput.getType())) {
			return false;
		}

		String[] passwordAndSalt;
		try {
			passwordAndSalt = userDao.getUserPasswordAndSaltOnRecord(userModel);
		}
		catch (PersistenceException e) {
			log.error("Caught exception while fetching password and salt from database", e);
			return false;
		}

		if (passwordAndSalt == null) {
			// No credential row for this user: a failed sign-in, not a server fault.
			return false;
		}

		String passwordOnRecord = passwordAndSalt[0];
		String saltOnRecord = passwordAndSalt[1];
		String currentPassword = credentialInput.getChallengeResponse();

		if (passwordOnRecord == null || saltOnRecord == null || currentPassword == null) {
			return false;
		}

		String passwordToHash = currentPassword + saltOnRecord;
		byte[] input = passwordToHash.getBytes(StandardCharsets.UTF_8);
		return passwordOnRecord.equals(hexString(MESSAGE_DIGEST.digest(input)));
	}

	private String hexString(byte[] block) {
		StringBuilder buf = new StringBuilder();
		char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
		int high;
		int low;
		for (byte aBlock : block) {
			high = ((aBlock & 0xf0) >> 4);
			low = (aBlock & 0x0f);
			buf.append(hexChars[high]);
			buf.append(hexChars[low]);
		}

		return buf.toString();
	}

	@Override
	public void close() {

	}

	@Override
	public int getUsersCount(RealmModel realmModel) {
		return userDao.getOpenmrsUserCount();
	}

	/**
	 * Keycloak 26 asks for streams rather than lists, and passes paging bounds as nullable Integers: a
	 * null means "unbounded", which the DAO expresses as 0 and Integer.MAX_VALUE.
	 */
	@Override
	public Stream<UserModel> searchForUserStream(RealmModel realmModel, Map<String, String> params, Integer firstResult,
	        Integer maxResults) {
		return userDao.searchForOpenmrsUserQuery(params, firstOr(firstResult), maxOr(maxResults)).stream()
		        .map(user -> (UserModel) new UserAdapter(session, realmModel, model, user));
	}

	@Override
	public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realmModel, String attribute, String value) {
		// OpenMRS users carry no Keycloak-style attributes, so there is nothing to search. Returning
		// empty is the honest answer; throwing would break admin console searches.
		return Stream.empty();
	}

	@Override
	public Stream<UserModel> getGroupMembersStream(RealmModel realmModel, GroupModel groupModel, Integer firstResult,
	        Integer maxResults) {
		// Groups are a Keycloak concept. OpenMRS roles are not exposed as groups here, so no user is a
		// member of any group as far as this provider is concerned.
		return Stream.empty();
	}

	private int firstOr(Integer firstResult) {
		return firstResult == null || firstResult < 0 ? 0 : firstResult;
	}

	private int maxOr(Integer maxResults) {
		return maxResults == null || maxResults < 0 ? Integer.MAX_VALUE : maxResults;
	}
}
