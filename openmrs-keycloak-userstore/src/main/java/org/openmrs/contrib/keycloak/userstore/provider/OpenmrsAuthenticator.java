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

import java.util.Map;
import java.util.Optional;
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
import org.openmrs.contrib.keycloak.userstore.data.OpenmrsSessionClient;
import org.openmrs.contrib.keycloak.userstore.data.UserAdapter;
import org.openmrs.contrib.keycloak.userstore.data.UserDao;
import org.openmrs.contrib.keycloak.userstore.models.OpenmrsUserModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Setter(AccessLevel.PACKAGE)
public class OpenmrsAuthenticator implements CredentialInputValidator, UserLookupProvider, UserStorageProvider, UserQueryProvider {

	private static final Logger log = LoggerFactory.getLogger(OpenmrsAuthenticator.class);

	protected KeycloakSession session;

	protected ComponentModel model;

	protected UserDao userDao;

	protected OpenmrsSessionClient sessionClient;

	public OpenmrsAuthenticator(KeycloakSession session, ComponentModel model, UserDao userDao,
	    OpenmrsSessionClient sessionClient) {
		this.session = session;
		this.model = model;
		this.userDao = userDao;
		this.sessionClient = sessionClient;
	}

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

		Integer userId = openmrsUserId(userModel);
		if (userId == null) {
			return false;
		}

		if (!userModel.isEnabled()) {
			// Rechecked here: Keycloak filters disabled users first, but isValid must not depend on that.
			log.info("Refusing the credential of OpenMRS user {}: the user is retired", userId);
			return false;
		}

		OpenmrsUserModel resolved;
		try {
			resolved = userDao.getOpenmrsUserByUserId(userId);
		}
		catch (PersistenceException e) {
			log.error("Could not read OpenMRS user {} to check a credential", userId, e);
			return false;
		}

		if (resolved == null || resolved.getUuid() == null) {
			return false;
		}

		/*
		 * The name from the same row the uuid came from, so both halves of the check describe one
		 * user. OpenMRS identifies a user with no username by its system_id.
		 */
		Optional<String> authenticated = sessionClient.authenticate(resolved.getIdentifier(),
		    credentialInput.getChallengeResponse());
		if (!authenticated.isPresent()) {
			return false;
		}

		/*
		 * A name can be one user's username and another's system_id, and OpenMRS answers for whichever
		 * it resolves, so a token would otherwise be minted for a user who never gave their password.
		 */
		// Trimmed: uuid is CHAR(38), which comes back padded to 38 under PAD_CHAR_TO_FULL_LENGTH.
		if (!authenticated.get().equals(resolved.getUuid().trim())) {
			log.warn("Refusing the credential of OpenMRS user {}: OpenMRS authenticated a different user", userId);
			return false;
		}

		return true;
	}

	/**
	 * @return the OpenMRS user_id this Keycloak id was built from, or null if it carries none.
	 */
	private Integer openmrsUserId(UserModel userModel) {
		String externalId = StorageId.externalId(userModel.getId());
		try {
			return Integer.valueOf(externalId);
		}
		catch (NumberFormatException e) {
			log.warn("Cannot check a credential for '{}': it does not identify an OpenMRS user", userModel.getId());
			return null;
		}
	}

	/**
	 * Called by Keycloak at the end of every session. It has to release the EntityManager created for
	 * this provider, or the connection behind it is never returned.
	 */
	@Override
	public void close() {
		userDao.close();
	}

	@Override
	public int getUsersCount(RealmModel realmModel) {
		return userDao.getOpenmrsUserCount();
	}

	@Override
	public Stream<UserModel> searchForUserStream(RealmModel realmModel, Map<String, String> params, Integer firstResult,
	        Integer maxResults) {
		return userDao.searchForOpenmrsUserQuery(params, firstOr(firstResult), maxOr(maxResults)).stream()
		        .map(user -> (UserModel) new UserAdapter(session, realmModel, model, user));
	}

	@Override
	public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realmModel, String attribute, String value) {
		return Stream.empty();
	}

	@Override
	public Stream<UserModel> getGroupMembersStream(RealmModel realmModel, GroupModel groupModel, Integer firstResult,
	        Integer maxResults) {
		return Stream.empty();
	}

	private int firstOr(Integer firstResult) {
		return firstResult == null || firstResult < 0 ? 0 : firstResult;
	}

	private int maxOr(Integer maxResults) {
		return maxResults == null || maxResults < 0 ? Integer.MAX_VALUE : maxResults;
	}
}
