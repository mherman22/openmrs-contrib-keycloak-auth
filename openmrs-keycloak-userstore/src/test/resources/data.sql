-- Passwords are stored the way OpenMRS stores them: the hash of the password concatenated with the
-- salt, in one of the three encodings OpenMRS's Security.hashMatches accepts. A fixture that held
-- plain text could not tell a working credential check from a broken one.

INSERT INTO users (user_id, username) VALUES (152,'admin');
INSERT INTO users (user_id, username) VALUES (186,'Sid');

-- SHA-512 of 'Sid123' + '123', which is what OpenMRS writes today.
INSERT INTO users (user_id, username, password, salt) VALUES (200,'SidVaish',
    '0dd4de366d0ee9c2cad07be099cdb954d8f60f8eedd4a968fa624e51bc8022ebb85e914bf39846a5dcbc9d89fd8b86a7143a1698136df05cf1ce3dc595df0321','123');

-- A user stored the way OpenMRS stores its admin account: no username, identified by system_id, with a
-- password. A distinct system_id so it cannot be confused with the row above that has 'admin' as its
-- username. SHA-512 of 'Sys123' + '999'.
INSERT INTO users (user_id, username, system_id, password, salt) VALUES (99,NULL,'99-1',
    '710cfad9cfcbd4b00d0bce89d9d812c904e307f9e34eb157e43e28e5de3f8f46007561b1fc8de0da85bdd2d4a770a5099076972ffe559bde3d7176aeb90a01a0','999');

-- SHA-1 of 'Legacy1' + 'l1': what OpenMRS wrote before SHA-512, still accepted by OpenMRS today.
INSERT INTO users (user_id, username, password, salt) VALUES (250,'legacy-sha1',
    '69fb1fc5895d79451f8c0f75fe0cd341be5a179f','l1');

-- SHA-1 of 'Ancient1' + 'a2' rendered by the historic hex routine, which dropped the leading zero of
-- every byte below 0x10: 38 characters where the same digest in full is 40, starting 'c7e3' where the
-- correct rendering starts '0c7e'. OpenMRS accepts these too.
INSERT INTO users (user_id, username, password, salt) VALUES (251,'legacy-oldhex',
    'c7e3c1354e9f14e5326eac8156465e1d53a9d0','a2');

-- Not written by OpenMRS, and no password can ever match it.
INSERT INTO users (user_id, username, password, salt) VALUES (254,'odd-hash','$2a$10$notAnOpenmrsPasswordHash','oh');

-- Retired in OpenMRS, with a password that is otherwise perfectly good: SHA-512 of 'Retired1' + 'r1'.
INSERT INTO users (user_id, username, password, salt, retired) VALUES (252,'retired-nurse',
    '467b17f2aa91750a81b611c1c1efc7599e9e9b9e484af0b7e79ed15d6494ecf8f21990c8d44283c5f4052158ff7f1a1e0c0faf5af091513d61b023d3ec71b5ff','r1',TRUE);

-- One user's username is another's system_id. OpenMRS refuses this pair when a user is saved, but no
-- database constraint prevents it, and the credential has to be read for the user that was resolved
-- rather than for whatever the name matches next. SHA-512 of 'Four001' + 'c4' and 'Four011' + 'c5'.
INSERT INTO users (user_id, username, password, salt) VALUES (400,'collide',
    '3030ef2a096cc11a89238a2af268fa9825fd2e17c495bc4bd7d5fca0b5fc0052de029521c692cfedb03a71b79caf2c65699f0439580fa4f7d1dfc1fa564f1c31','c4');
INSERT INTO users (user_id, username, system_id, password, salt) VALUES (401,NULL,'collide',
    'b3e229442709459fc811a049f7a6e1933865f5160f2269c9a3b2641f1bac53f4fefbabba6f0f00e6ef8acfc9e1b55a6f5aa619ad1ab71bb45ec38d62fcc17970','c5');

-- An ordinary user, whom the lockout tests lock and unlock by writing the timestamp OpenMRS would
-- have written. SHA-512 of 'Locked1' + 'k1'.
INSERT INTO users (user_id, username, password, salt) VALUES (253,'locked-out',
    'a1b84ea953b996c719f140eb770a1bd96ed0bc7f360a15264b2ddba5d3262393d0e1f4fcc8bf02834d891e3fff8995e4e4c437fea8c146ca0df324a93358fcad','k1');
INSERT INTO user_property (user_id, property, property_value) VALUES (253,'lockoutTimestamp','0');
INSERT INTO user_property (user_id, property, property_value) VALUES (253,'loginAttempts','7');

-- Ten minutes rather than the default five, so a test can tell that this is being read.
INSERT INTO global_property (property, property_value) VALUES ('security.unlockAccountWaitingTime','10');
