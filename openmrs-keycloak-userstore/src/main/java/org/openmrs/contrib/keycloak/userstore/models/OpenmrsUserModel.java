/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.contrib.keycloak.userstore.models;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.Data;

@Entity
@Table(name = "users")
@Data
public class OpenmrsUserModel {

	@Id
	@Column(name = "user_id")
	private Integer userId;

	@OneToOne
	@JoinColumn(name = "person_id")
	private PersonModel person;

	private String username;

	@Column(name = "system_id")
	private String systemId;

	private String email;

	/**
	 * Boolean rather than boolean: the column is nullable, and a primitive would read NULL as not
	 * retired.
	 */
	private Boolean retired;
}
