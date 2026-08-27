# OpenMRS user federation for Keycloak

A Keycloak `UserStorageProvider` and `CredentialInputValidator` that finds users in the OpenMRS
`users` table and has OpenMRS itself check their passwords, so clinicians sign in with the OpenMRS
password they already have and there is no second directory to keep in step.

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
   and password for the OpenMRS database, and the **OpenMRS base URL** — the one Keycloak can reach,
   which inside Docker is the service name rather than `localhost`.

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
`security.unlockAccountWaitingTime` minutes (5 by default). Because OpenMRS is what authenticates
here, that lockout applies to this door as well, and **guesses at the Keycloak form count towards
it**: `HibernateContextDAO.authenticate` increments `loginAttempts` and, once locked, throws before
it reads the password.

That is the behaviour this provider exists to keep consistent, and it is also a new surface. Anyone
who can reach the Keycloak login form can lock a named clinician out of OpenMRS itself for
`security.unlockAccountWaitingTime` minutes, without knowing any password.

Keycloak's own brute force detection is what meters guesses before they reach OpenMRS, and
Keycloak creates realms with it **off**. Once enabled, its default `failureFactor` is 30, four times
looser than the OpenMRS threshold it is standing in for. Check what your realm actually has:

```
kcadm.sh get realms/<realm> --fields bruteForceProtected,failureFactor,waitIncrementSeconds,permanentLockout
```

Until this is on, the Keycloak login form is an unmetered password oracle against the OpenMRS user
table — and a more attractive one than the OpenMRS form, because it looks like Keycloak.

### Reaching OpenMRS: HTTPS, and no cookie jar

Credentials are checked by sending them to OpenMRS, so **the base URL must be `https` anywhere the
two are not on the same host**. The password is in an `Authorization: Basic` header on every login.

The client that sends it must never carry a cookie between validations. OpenMRS's
`/ws/rest/v1/session` reports the state of the *session*, not of the credentials on the request: a
`JSESSIONID` from one successful login makes it answer `authenticated:true` to a wrong password, and
to no password at all. `OpenmrsSessionClient` builds a `java.net.http.HttpClient` with no cookie
handler for this reason, and Keycloak's shared `HttpClientProvider` is deliberately not used —
its cookie behaviour is operator-configurable (`disable-cookies`), so a setting changed for an
unrelated integration would turn this credential check into "accept every password".

Each validation also leaves OpenMRS holding a server-side session that is never reclaimed, including
for failed guesses, until it idles out.

The client is built once per provider factory and holds the base URL it was built with, as the
`EntityManagerFactory` holds the JDBC settings. **Changing either in the admin console takes effect
at the next Keycloak restart, not at the next login.**

## Connection pool sizing

With `NO_CACHE`, a login is two queries against the OpenMRS database — the user lookup, and a
re-read of that user to get its uuid — plus one HTTP request to OpenMRS, which is what decides the
credential.

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
| JPA entities, checked by `hbm2ddl validate` | `users`: `user_id`, `uuid`, `person_id`, `username`, `system_id`, `email`, `retired`<br>`person`: `person_id`, `gender`<br>`person_name`: `person_name_id`, `person_id`, `given_name`, `middle_name`, `family_name` |

No native SQL, and no credential columns: `password`, `salt`, `user_property` and `global_property`
are not read at all. Those went when the credential check moved to OpenMRS.

`hbm2ddl validate` runs when the `EntityManagerFactory` is built, which happens when the federation
component is saved and again on the first use after a restart.

- **A mapped column that is renamed or removed** fails validation, so the `EntityManagerFactory`
  cannot be built. Saving the component in the admin console reports it immediately. After a
  restart, it takes every login with it.
These are core OpenMRS tables and have been stable from 1.9 through 2.8, so the likelihood is low
and the blast radius is everyone. On an OpenMRS upgrade: run this project's tests, whose schema is
the same shape, and then point a Keycloak at a copy of the upgraded database and save the federation
component — that is the cheapest way to run `validate` against the real thing.

## How a password is checked

OpenMRS checks it. This provider sends the name it resolved the user by and the password as it was
typed to `GET /ws/rest/v1/session`, as Basic auth, and reads the answer.

That means whatever the deployment has configured decides the login — the hash encoding, password
expiry, lockout, and any `DelegatingAuthenticationScheme` in use — rather than a second
implementation here agreeing with it by hand.

Two things about the answer are easy to get wrong, and both are load-bearing:

- **It is always `200`.** A wrong password, an unknown user and no credentials at all all return
  `200` with `{"authenticated":false}`. The status code says nothing; the `authenticated` field is
  the only signal.
- **`authenticated:true` is not enough.** A name can be one user's `username` and another's
  `system_id`, and OpenMRS answers for whichever it resolves — so the response's `user.uuid` must
  equal the uuid of the user Keycloak resolved. Otherwise a token gets minted for a user who never
  gave their password.

## Deliberate differences from OpenMRS's own authenticate

- **No password changes.** This provider never writes to the OpenMRS schema itself. It does cause
  OpenMRS to record a sign-in, because OpenMRS is the one authenticating: a failed attempt at the
  Keycloak form increments that user's `loginAttempts`, and a successful one writes
  `lastLoginTimestamp` and resets the counter.
- **A retired user is reported to Keycloak as disabled** and refused at the credential check, but is
  still found by lookups, so an administrator can see the account they retired. The login form
  therefore says "Account is disabled" where OpenMRS would say "Invalid username and/or password".
- **A locked-out user is refused as an ordinary bad credential.** OpenMRS raises
  "Invalid number of connection attempts. Please try again later.", but a `CredentialInputValidator`
  can only answer yes or no, so the Keycloak form shows a bad-password message.
- **A digits-only login is not expanded to a check-digit system id.** OpenMRS matches a login of
  `1234` against the system id `123-4`; users who rely on that must type the system id as stored.
- **Attribute search and group membership answer with empty streams.** OpenMRS users carry neither,
  and throwing breaks admin console searches.
