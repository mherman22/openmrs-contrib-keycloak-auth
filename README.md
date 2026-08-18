# OpenMRS user federation for Keycloak

A Keycloak `UserStorageProvider` and `CredentialInputValidator` that authenticates against the
OpenMRS `users` table, so clinicians sign in with the OpenMRS password they already have and there
is no second directory to keep in step.

Built for **Keycloak 26.7.1**: a plain JAR in `providers/`, Java 17 bytecode, the Stream-based query
SPI, and every dependency pinned to what that Keycloak already ships, in `provided` scope. The
provider binds to the container's libraries rather than carrying its own, so compiling against
anything newer moves a breakage from build time to runtime.

```
mvn clean package
# openmrs-keycloak-userstore/target/openmrs-keycloak-userstore-1.0.0-SNAPSHOT.jar
```

## Deploying

1. Copy the JAR into `/opt/keycloak/providers`.

2. **Copy a MySQL JDBC driver in beside it.** Keycloak ships one for its own datasource, in
   `lib/lib/main`, but Quarkus does not expose that to provider classloaders — and with an embedded
   development database it is not there at all. Without the driver, creating the federation
   component fails with:

   ```
   ClassNotFoundException: com.mysql.cj.jdbc.Driver
   ```

   Use the same version the pom pins (`com.mysql:mysql-connector-j`, currently 9.6.0), and move the
   two together. The driver talks to both MySQL and MariaDB; no dialect is configured, because
   Hibernate 6 removed the versioned MySQL dialects and detects the dialect from JDBC metadata,
   which is what a provider deployed against either engine wants. Connecting to MariaDB through
   this driver logs `HHH000511 ... 5.5.5 version ... is no longer supported` — MariaDB prefixes its
   version string, Hibernate reads the prefix, and it is harmless.

3. Restart Keycloak, then add the provider under **User federation** and fill in the JDBC URL, user
   and password for the OpenMRS database.

   Against MySQL 8, the default URL in the form (`...?useSSL=false`) fails validation with
   `Public Key Retrieval is not allowed`: MySQL 8 authenticates with `caching_sha2_password`, which
   over an unencrypted connection needs `allowPublicKeyRetrieval=true` in the URL — or, better, a
   connection that is actually encrypted.

## Realm settings this provider depends on

These are not code. They are realm configuration, and the provider is not safe or usable without
them.

### Cache policy: `NO_CACHE`

OpenMRS is the source of truth for who may sign in, and it changes underneath Keycloak: an
administrator retires a user, OpenMRS locks an account after failed sign-ins, someone changes a
password. Keycloak's default policy caches federated users, and a cached user goes on
authenticating after OpenMRS has stopped allowing it. `NO_CACHE` is the setting that makes
retirement and lockout take effect at the next login.

The cost is that **every login reads the OpenMRS database** — see the next section.

### `VERIFY_PROFILE`: disabled

Keycloak 24 and later evaluate the user profile on every login and, when a required field is
missing, hand the user the profile form. This provider supplies a username, and an email address
only for the users who have one; it supplies no first or last name at all. OpenMRS does not require
an email address, and Keycloak cannot write one back through a read-only federation provider, so
the required action cannot be satisfied and cannot be dismissed: every federated login is refused
with **"Account is not fully set up"**, and nothing on the user record explains why.

Turn it off under **Authentication → Required actions → Verify Profile**.

### Brute force detection: enabled, with a threshold no looser than OpenMRS's

OpenMRS counts failed sign-ins per user and locks the account past
`security.allowedFailedLoginsBeforeLockout` (7 by default) for
`security.unlockAccountWaitingTime` minutes (5 by default). This provider **reads** that lockout, so
an account OpenMRS has locked is refused here too — but it writes nothing back, so failures at the
Keycloak login form never count towards that threshold.

Keycloak's own brute force detection is therefore the only thing metering guesses at this door, and
Keycloak creates realms with it **off**. Once enabled, its default `failureFactor` is 30, four times
looser than the OpenMRS threshold it is standing in for. Check what your realm actually has:

```
kcadm.sh get realms/<realm> --fields bruteForceProtected,failureFactor,waitIncrementSeconds,permanentLockout
```

Until this is on, the Keycloak login form is an unmetered password oracle against the OpenMRS user
table — and a more attractive one than the OpenMRS form, because it looks like Keycloak.

## Connection pool sizing

With `NO_CACHE`, a login is three queries against the OpenMRS database — the user lookup, the
lockout property, and the credential — plus a fourth to read the unlock waiting time when the
account is actually locked.

Those run through one `EntityManagerFactory` per provider factory, using **Hibernate's built-in
connection pool, capped at 20** (`PersistenceUnitInfoImpl`). Two consequences:

- Keycloak holds at most twenty connections to the OpenMRS database. Size `max_connections` on the
  OpenMRS server for that on top of OpenMRS's own usage.
- Twenty is also the ceiling on concurrent logins; past it, requests wait for a connection.

Hibernate says plainly that this pool is not meant for production. It is stated explicitly rather
than left at its default so the ceiling is visible, because it is the number that runs out. When a
provider leaked its `EntityManager` — the provider is created per session and must release it in
`close()` — the pool was exhausted after a few hundred logins and the server answered *"The internal
connection pool has reached its maximum size"* to every request, including its own admin console,
which reads as Keycloak having failed rather than this provider. If this deployment outgrows twenty
connections, the change to make is a real pool, and it belongs in `PersistenceUnitInfoImpl`.

Sixty consecutive logins against MySQL 8.4 hold at one connection and drop to zero when the factory
closes. That check is worth repeating after any change to the credential path.

## What this reads, and what happens when OpenMRS's schema changes

The two systems are now coupled at the schema level. This is what the coupling consists of:

| Read through | Tables and columns |
| --- | --- |
| JPA entities, checked by `hbm2ddl validate` | `users`: `user_id`, `person_id`, `username`, `system_id`, `email`, `retired`<br>`person`: `person_id`, `gender`<br>`person_name`: `person_name_id`, `person_id`, `given_name`, `middle_name`, `family_name` |
| Native SQL, not checked | `users`: `password`, `salt`, `retired`<br>`user_property`: `user_id`, `property`, `property_value`<br>`global_property`: `property`, `property_value` |

`hbm2ddl validate` runs when the `EntityManagerFactory` is built, which happens when the federation
component is saved and again on the first use after a restart. The two halves of the table fail
differently:

- **A mapped column that is renamed or removed** fails validation, so the `EntityManagerFactory`
  cannot be built. Saving the component in the admin console reports it immediately. After a
  restart, it takes every login with it.
- **A column used only by a native query** fails when that query runs — at the first login. The
  credential check answers `false` on a `PersistenceException`, so this presents as every user's
  password having suddenly become wrong, with the real exception only in the server log.

These are core OpenMRS tables and have been stable from 1.9 through 2.8, so the likelihood is low
and the blast radius is everyone. On an OpenMRS upgrade: run this project's tests, whose schema is
the same shape, and then point a Keycloak at a copy of the upgraded database and save the federation
component — that is the cheapest way to run `validate` against the real thing.

## How a password is checked

The same three encodings OpenMRS's own `Security.hashMatches` accepts, tried in the same order
against the hash of the password concatenated with the user's salt:

1. SHA-512, hex, zero-padded per byte — what OpenMRS writes today
2. SHA-1, hex, zero-padded per byte — what it wrote before that
3. SHA-1 rendered by the historic routine that dropped the leading zero of every byte below `0x10`

A database that has ever run an older OpenMRS holds all three, and OpenMRS still accepts all three,
so a provider that checks only the first locks out users who can sign in to OpenMRS today — and
tells them their password is wrong. A stored hash in none of those shapes is logged, by user id,
saying that no password can match it.

## Deliberate differences from OpenMRS's own authenticate

- **Nothing is written back.** No password changes, no `loginAttempts`, no `lastLoginTimestamp`.
  This provider validates credentials and nothing else.
- **A retired user is reported to Keycloak as disabled** and refused at the credential check, but is
  still found by lookups, so an administrator can see the account they retired. The login form
  therefore says "Account is disabled" where OpenMRS would say "Invalid username and/or password".
- **A locked-out user is refused as an ordinary bad credential.** A `CredentialInputValidator`
  cannot put OpenMRS's "Invalid number of connection attempts. Please try again later." on the
  Keycloak login form.
- **A digits-only login is not expanded to a check-digit system id.** OpenMRS matches a login of
  `1234` against the system id `123-4`; users who rely on that must type the system id as stored.
- **Attribute search and group membership answer with empty streams.** OpenMRS users carry neither,
  and throwing breaks admin console searches.
