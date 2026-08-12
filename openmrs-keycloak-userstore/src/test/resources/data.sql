INSERT INTO users (user_id, username) VALUES (152,'admin');
INSERT INTO users (user_id, username) VALUES (186,'Sid');
INSERT INTO users (user_id, username, password, salt) VALUES (200,'SidVaish','Sid123','123');

-- A user stored the way OpenMRS stores its admin account: no username, identified by system_id, with a
-- password. A distinct system_id so it cannot be confused with the row above that has 'admin' as its
-- username.
INSERT INTO users (user_id, username, system_id, password, salt) VALUES (99,NULL,'99-1','Sys123','999');
