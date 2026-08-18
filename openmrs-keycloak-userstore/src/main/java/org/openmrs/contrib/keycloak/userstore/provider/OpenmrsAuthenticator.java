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

	private static final Logger log = LoggerFactory.getLogger(OpenmrsAuthenticator.class);

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

		Integer userId = openmrsUserId(userModel);
		if (userId == null) {
			return false;
		}

		if (!userModel.isEnabled()) {
			// Retired in OpenMRS. Keycloak checks this itself before it asks us, but this is the
			// credential check: it answers for itself rather than relying on having been asked in the
			// right order.
			log.info("Refusing the credential of OpenMRS user {}: the user is retired", userId);
			return false;
		}

		String[] passwordAndSalt;
		try {
			passwordAndSalt = userDao.getUserPasswordAndSaltOnRecord(userId);
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
			// A user who has never had a password set. OpenMRS leaves both columns null for them, and
			// they cannot sign in anywhere until one is set.
			return false;
		}

		if (hashMatches(passwordOnRecord, currentPassword + saltOnRecord)) {
			return true;
		}

		if (!isRecognisedHashFormat(passwordOnRecord)) {
			log.warn("The password on record for OpenMRS user {} is {} characters long and is neither a SHA-512 nor a "
			        + "SHA-1 hash. No password can match it, so this user cannot sign in until their OpenMRS password "
			        + "is set again.",
			    userId, passwordOnRecord.length());
		}

		return false;
	}

	/**
	 * @return the OpenMRS user_id this Keycloak id was built from, or null if it does not carry one.
	 *         <p>
	 *         The credential is read for the user the lookup resolved, not for whatever the name
	 *         matches a second time.
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
	 * The same three encodings OpenMRS's own {@code Security.hashMatches} accepts, in the order it
	 * tries them: SHA-512 hex, SHA-1 hex, and SHA-1 rendered by the historic hex routine that dropped
	 * the leading zero of every byte below 0x10. A database that has ever run an older OpenMRS holds
	 * all three, and they are still what OpenMRS accepts today, so supporting only the first left users
	 * who can sign in to OpenMRS unable to sign in through Keycloak -- indistinguishably, to them, from
	 * having mistyped their password.
	 */
	private boolean hashMatches(String hashOnRecord, String passwordAndSalt) {
		byte[] input = passwordAndSalt.getBytes(StandardCharsets.UTF_8);
		return matches(hashOnRecord, hexString(digest("SHA-512", input)))
		        || matches(hashOnRecord, hexString(digest("SHA-1", input)))
		        || matches(hashOnRecord, incorrectHexString(digest("SHA-1", input)));
	}

	/**
	 * A digest per call. The single shared MessageDigest this replaces was stateful and unsynchronised,
	 * so two logins at once could interleave into one another's hash and fail for no reason the user
	 * could see or repeat -- and with NO_CACHE, every login goes through here.
	 */
	private static byte[] digest(String algorithm, byte[] input) {
		try {
			return MessageDigest.getInstance(algorithm).digest(input);
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(algorithm + " is needed to check OpenMRS passwords", e);
		}
	}

	/** Compared in constant time: String.equals stops at the first character that differs. */
	private static boolean matches(String hashOnRecord, String candidate) {
		return MessageDigest.isEqual(hashOnRecord.getBytes(StandardCharsets.UTF_8),
		    candidate.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * The shapes {@link #hashMatches} can produce: 128 hex characters of SHA-512, or at most 40 of
	 * SHA-1, fewer where the historic routine dropped leading zeros. Anything else was written by
	 * something that is not OpenMRS, and no password will ever match it, so say so once rather than
	 * leaving it as an ordinary failed sign-in.
	 */
	private static boolean isRecognisedHashFormat(String hashOnRecord) {
		if (hashOnRecord.isEmpty() || (hashOnRecord.length() != 128 && hashOnRecord.length() > 40)) {
			return false;
		}

		return hashOnRecord.chars().allMatch(character -> Character.digit(character, 16) >= 0);
	}

	/**
	 * OpenMRS's {@code Security.incorrectHexString}: Integer.toHexString of each byte, which renders
	 * anything below 0x10 as a single character. Hashes written before that was fixed are still in
	 * OpenMRS databases and OpenMRS still accepts them.
	 */
	private String incorrectHexString(byte[] block) {
		StringBuilder buf = new StringBuilder();
		for (byte aBlock : block) {
			buf.append(Integer.toHexString(aBlock & 0xFF));
		}

		return buf.toString();
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
