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

import java.util.List;
import java.util.Map;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.persistence.TypedQuery;
import org.apache.commons.lang3.NotImplementedException;
import org.openmrs.contrib.keycloak.userstore.models.OpenmrsUserModel;

public class UserDao {

	private final EntityManager em;

	public UserDao(EntityManager em) {
		this.em = em;
	}

	/**
	 * Releases the EntityManager, and with it the JDBC connection behind it.
	 * <p>
	 * Keycloak creates a provider per session and closes it when the session ends. This was never
	 * called, so every authentication leaked a connection: Hibernate's built-in pool holds twenty, and
	 * a server that had served a few hundred logins began answering "The internal connection pool has
	 * reached its maximum size" to every request — including the admin console, which made it look like
	 * Keycloak itself had failed rather than this provider.
	 */
	public void close() {
		if (em != null && em.isOpen()) {
			em.close();
		}
	}

	/**
	 * @return the user, or null if there is no such user.
	 *         <p>
	 *         Null, not an exception. Keycloak's federation contract is that a lookup for a user who
	 *         does not exist answers null; getSingleResult throws NoResultException instead, which
	 *         Keycloak reports to the browser as "Unexpected error when handling authentication request
	 *         to identity provider". Every mistyped username at the login form produced that page.
	 */
	public OpenmrsUserModel getOpenmrsUserByUsername(String username) {
		// Username or system_id, which is what OpenMRS's own getUserByUsername matches. Matching only on
		// username left the admin account, and any user created without one, unable to authenticate at
		// all: those rows carry the name in system_id and NULL in username.
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
	 * @return the password and salt on record, or null if there is no such user.
	 *         <p>
	 *         Keyed by user_id: the identity the lookup already resolved, and the same key OpenMRS uses
	 *         at this point in its own authenticate. Matching the name again ran a second query over
	 *         the same "username or system_id" predicate, unordered and in native SQL rather than JPQL,
	 *         so it was not guaranteed to answer with the row the identity had come from. OpenMRS
	 *         rejects a username that collides with another user's system_id when a user is saved, but
	 *         nothing in the database enforces that.
	 */
	public String[] getUserPasswordAndSaltOnRecord(Integer userId) {
		Query query = em.createNativeQuery("select password, salt from users u where u.user_id = :userId");
		query.setParameter("userId", userId);

		// Null rather than an exception, for the same reason as above: a user with no row here is a
		// failed credential, not a server fault.
		Object row = query.getResultStream().findFirst().orElse(null);
		if (row == null) {
			return null;
		}

		// Either column may be null, for a user who has never had a password set. Mapping the row
		// through Object::toString threw a NullPointerException out of the credential check, and
		// because isValid catches only PersistenceException it reached the browser as
		// "Unexpected error when handling authentication request" rather than a failed sign-in.
		Object[] columns = (Object[]) row;
		return new String[] { asString(columns[0]), asString(columns[1]) };
	}

	private static String asString(Object column) {
		return column == null ? null : column.toString();
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
		// Every clause is "this criterion was not given, or it matches", combined with and. They used to
		// be combined with or, which made the query true for every user as soon as any one criterion was
		// absent: a search by username alone returned the whole table, and which user came back first
		// depended on nothing more than user_id order.
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
