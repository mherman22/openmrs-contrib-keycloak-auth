/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.contrib.keycloak.userstore.data;

import java.sql.Clob;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.persistence.TypedQuery;
import org.apache.commons.lang3.NotImplementedException;
import org.openmrs.contrib.keycloak.userstore.models.OpenmrsUserModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserDao {

	/** OpenMRS's default for security.unlockAccountWaitingTime, in minutes. */
	private static final long DEFAULT_UNLOCK_WAIT_MINUTES = 5;

	private static final Logger log = LoggerFactory.getLogger(UserDao.class);

	private final EntityManager em;

	public UserDao(EntityManager em) {
		this.em = em;
	}

	public void close() {
		if (em != null && em.isOpen()) {
			em.close();
		}
	}

	/**
	 * Answers null rather than throwing: Keycloak's federation contract treats a lookup for a missing
	 * user as null, and getSingleResult would throw NoResultException instead.
	 *
	 * @return the user, or null if there is no such user.
	 */
	public OpenmrsUserModel getOpenmrsUserByUsername(String username) {
		// Matches system_id too: OpenMRS identifies a user with no username by it.
		TypedQuery<OpenmrsUserModel> query = em.createQuery(
		    "select u from OpenmrsUserModel u where u.username = :identifier or u.systemId = :identifier",
		    OpenmrsUserModel.class);
		query.setParameter("identifier", username);
		return query.getResultStream().findFirst().orElse(null);
	}

	/** @return the user, or null if there is no such user. See {@link #getOpenmrsUserByUsername}. */
	public OpenmrsUserModel getOpenmrsUserByUserId(Integer userId) {
		TypedQuery<OpenmrsUserModel> query = em.createQuery("select u from OpenmrsUserModel u where u.userId = :userId",
		    OpenmrsUserModel.class);
		query.setParameter("userId", userId);
		return query.getResultStream().findFirst().orElse(null);
	}

	/** @return the user, or null if there is no such user. See {@link #getOpenmrsUserByUsername}. */
	public OpenmrsUserModel getOpenmrsUserByEmail(String email) throws NotImplementedException {
		TypedQuery<OpenmrsUserModel> query = em.createQuery("select u from OpenmrsUserModel u where u.email = :email",
		    OpenmrsUserModel.class);
		query.setParameter("email", email);
		return query.getResultStream().findFirst().orElse(null);
	}

	/**
	 * Keyed by user_id rather than by name: one user's username can be another's system_id, so matching
	 * the name a second time can answer with the other user's credential.
	 *
	 * @return the password and salt on record, or null if there is no such user or they are retired.
	 */
	public String[] getUserPasswordAndSaltOnRecord(Integer userId) {
		Query query = em
		        .createNativeQuery("select password, salt from users u where u.user_id = :userId and u.retired = false");
		query.setParameter("userId", userId);

		Object row = query.getResultStream().findFirst().orElse(null);
		if (row == null) {
			return null;
		}

		// Null elements, not a null array: both columns are null for a user with no password set.
		Object[] columns = (Object[]) row;
		return new String[] { asString(columns[0]), asString(columns[1]) };
	}

	/**
	 * @return whether OpenMRS has this account locked out at this moment.
	 */
	public boolean isLockedOutInOpenmrs(Integer userId) {
		String lockedAt = userProperty(userId, "lockoutTimestamp");
		if (lockedAt == null || lockedAt.isBlank() || "0".equals(lockedAt.trim())) {
			return false;
		}

		long lockedAtMs;
		try {
			lockedAtMs = Long.parseLong(lockedAt.trim());
		}
		catch (NumberFormatException e) {
			// Fail open as OpenMRS does: an unreadable timestamp must not lock the account.
			log.warn("Bad value stored in the lockoutTimestamp user property of OpenMRS user {}: '{}'", userId, lockedAt);
			return false;
		}

		return System.currentTimeMillis() - lockedAtMs <= unlockWaitMs();
	}

	private long unlockWaitMs() {
		String waitingTime = globalProperty("security.unlockAccountWaitingTime");
		if (waitingTime != null && !waitingTime.isBlank()) {
			try {
				return TimeUnit.MINUTES.toMillis(Long.parseLong(waitingTime.trim()));
			}
			catch (NumberFormatException e) {
				log.warn("Unable to read the global property security.unlockAccountWaitingTime as a number: '{}'. "
				        + "Using the OpenMRS default of {} minutes.",
				    waitingTime, DEFAULT_UNLOCK_WAIT_MINUTES);
			}
		}

		return TimeUnit.MINUTES.toMillis(DEFAULT_UNLOCK_WAIT_MINUTES);
	}

	private String userProperty(Integer userId, String property) {
		Query query = em.createNativeQuery(
		    "select property_value from user_property where user_id = :userId and property = :property");
		query.setParameter("userId", userId);
		query.setParameter("property", property);
		return firstValue(query);
	}

	private String globalProperty(String property) {
		Query query = em.createNativeQuery("select property_value from global_property where property = :property");
		query.setParameter("property", property);
		return firstValue(query);
	}

	/**
	 * The first value of a single column query, or null for no row -- and for a row whose value is
	 * null, which these columns allow. Stream.findFirst cannot carry a null and throws on one.
	 */
	private static String firstValue(Query query) {
		List<?> results = query.setMaxResults(1).getResultList();
		return results.isEmpty() ? null : asString(results.get(0));
	}

	private static String asString(Object column) {
		if (column == null) {
			return null;
		}

		// A CLOB column can arrive as a java.sql.Clob, whose toString is a handle, not the value.
		if (column instanceof Clob) {
			Clob clob = (Clob) column;
			try {
				return clob.getSubString(1, (int) clob.length());
			}
			catch (SQLException e) {
				log.error("Could not read a property value out of the OpenMRS database", e);
				return null;
			}
		}

		return column.toString();
	}

	public int getOpenmrsUserCount() {
		Number count = em.createQuery("select count(u) from OpenmrsUserModel u", Long.class).getSingleResult();
		return count.intValue();
	}

	public List<OpenmrsUserModel> getAllOpenmrsUsers(int firstResult, int maxResult) {
		return em.createQuery("select u from OpenmrsUserModel u", OpenmrsUserModel.class).setFirstResult(firstResult)
		        .setMaxResults(maxResult).getResultList();
	}

	public List<OpenmrsUserModel> searchForOpenmrsUserQuery(Map<String, String> map, int firstResult, int maxResult) {
		// Combined with and: with or, an absent criterion makes the whole query true for every user.
		return em
		        .createQuery("select u from OpenmrsUserModel u left outer join u.person.names n "
		                + "where (:username is null or lower(u.username) like lower(:username)) and "
		                + "(:email is null or lower(u.email) like lower(:email)) and "
		                + "(:first is null or lower(n.givenName) like lower(:first)) and "
		                + "(:last is null or lower(n.familyName) like lower(:last))",
		            OpenmrsUserModel.class)
		        .setParameter("username", map.get("username")).setParameter("email", map.get("email"))
		        .setParameter("first", map.get("first")).setParameter("last", map.get("last")).setFirstResult(firstResult)
		        .setMaxResults(maxResult).getResultList();
	}
}
