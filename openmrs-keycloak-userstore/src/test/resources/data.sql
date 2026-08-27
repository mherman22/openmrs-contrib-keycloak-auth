-- Whether a password is right is OpenMRS's answer, not this fixture's: these rows exist to be
-- looked up and identified by uuid.

INSERT INTO users (user_id, uuid, username) VALUES (152,'uuid-user-152','admin');
INSERT INTO users (user_id, uuid, username) VALUES (186,'uuid-user-186','Sid');
INSERT INTO users (user_id, uuid, username) VALUES (200,'uuid-user-200','SidVaish');

-- No username, identified by system_id: the shape OpenMRS uses for a user created without one, and
-- the shape its own admin account ships in.
INSERT INTO users (user_id, uuid, username, system_id) VALUES (99,'uuid-user-99',NULL,'99-1');

-- Retired in OpenMRS.
INSERT INTO users (user_id, uuid, username, retired) VALUES (252,'uuid-user-252','retired-nurse',TRUE);

-- One user's username is another's system_id. OpenMRS refuses this pair when a user is saved, but no
-- database constraint prevents it, so a name alone does not identify which user OpenMRS authenticated.
INSERT INTO users (user_id, uuid, username) VALUES (400,'uuid-user-400','collide');
INSERT INTO users (user_id, uuid, username, system_id) VALUES (401,'uuid-user-401',NULL,'collide');
