CREATE TABLE person (
  person_id int NOT NULL PRIMARY KEY,
  gender varchar(50) NOT NULL);

CREATE TABLE person_name (
  person_name_id int NOT NULL PRIMARY KEY,
  person_id int NOT NULL,
  given_name varchar(255),
  middle_name varchar(255),
  family_name varchar(255));

ALTER TABLE person_name
    ADD FOREIGN KEY (person_id)
    REFERENCES person(person_id);

CREATE TABLE users (
  user_id int NOT NULL PRIMARY KEY,
  -- OpenMRS's REST session response identifies the authenticated user by this.
  uuid char(38) NOT NULL,
  person_id int DEFAULT NULL,
  -- Nullable, as OpenMRS has it: a user created without a username is identified by system_id alone.
  username varchar(255) DEFAULT NULL,
  system_id varchar(50) DEFAULT NULL,
  email varchar(255) DEFAULT NULL,
  password varchar(128) DEFAULT NULL,
  salt varchar(128) DEFAULT NULL,
  -- How OpenMRS disables an account: not null, and false unless the user has been retired.
  retired boolean NOT NULL DEFAULT FALSE);

ALTER TABLE users
    ADD FOREIGN KEY (person_id)
    REFERENCES person (person_id);

