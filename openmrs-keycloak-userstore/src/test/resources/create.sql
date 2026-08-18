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
  person_id int DEFAULT NULL,
  -- Nullable, as OpenMRS has it. The admin account ships with no username and is identified by its
  -- system_id; declaring this NOT NULL here made a whole class of user impossible to represent in a
  -- test, which is why a lookup that ignored system_id went unnoticed.
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

-- OpenMRS counts failed sign-ins and locks accounts through these two tables: lockoutTimestamp and
-- loginAttempts per user, and security.unlockAccountWaitingTime for the whole installation. Declared
-- with the types OpenMRS uses, clob included, since how the driver hands those back is the question.
CREATE TABLE user_property (
  user_id int NOT NULL,
  property varchar(255) NOT NULL,
  property_value clob,
  PRIMARY KEY (user_id, property));

CREATE TABLE global_property (
  property varchar(255) NOT NULL PRIMARY KEY,
  property_value clob);
