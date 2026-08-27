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
import jakarta.persistence.TypedQuery;
import org.apache.commons.lang3.NotImplementedException;
import org.openmrs.contrib.keycloak.userstore.models.OpenmrsUserModel;

public class UserDao {

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
