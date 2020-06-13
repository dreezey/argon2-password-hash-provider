# Introduction
This project introduces Argon2 Password Hashing for Keycloak, there are 2 versions:
* V1.x, which uses `de.mkammerer.argon2` as the library, more can be found on the [GitHub Project](https://github.com/phxql/argon2-jvm). (Compatible with Keycloak V8.x and above)
* V2.x, which inherits Keycloak's [BouncyCastle V1.62](https://www.bouncycastle.org/releasenotes.html#1.61) with native support for Argon2 (Compatible with Keycloak V10.x and above only)

V1.x is packaged as an EAR due to external dependencies. I will no longer maintain this version. Choose this one if you don't Keycloak V10.x or above.

V2.x is packaged as a JAR since it uses Keycloak's provided libraries. This will be the **actively maintained** version for now.

Both are deployed using [Keycloak Deployer](https://www.keycloak.org/docs/latest/server_development/index.html#using-the-keycloak-deployer).

# Build
Build the project using:
```
mvn clean package;
```

This will build the provider JAR:
```
[INFO] ----------< be.cronos.keycloak:argon2-password-hash-provider >----------
[INFO] Building Argon2 Password Hash Provider 2.x.x
[INFO] --------------------------------[ jar ]---------------------------------
```

# Installation
Simply hot-deploy the module:
```
cp target/argon2-password-hash-provider-*.jar /opt/keycloak/standalone/deployments/argon2-password-hash-provider.jar;
```

# Keycloak configuration
Finally, in the Keycloak realm of your choosing, activate the Argon2 password hashing via:
`Authentication > Password Policy` and then selecting the policy `Hashing Algorithm` and name it: `argon2`.

Further tuning can be done by the other Policy Providers:
* `Argon2 Version` --> you can choose which Argon2 version to use, either: `10` or `13` (default: 13)
* `Argon2 Variant` --> you can choose which Argon2 variant to use, either: `ARGON2i`, `ARGON2d` or `ARGON2id` (default: ARGON2id)
* `Argon2 Iterations` --> tune the number of iterations the provider will perform (default: 1)
* `Argon2 Memory Usage` --> tune the memory limitation (in KB) of the provider (default: 65536)
* `Argon2 Parallelism` --> tune the number of threads and memory lanes  (default: 1)
* `Argon2 Salt Length` --> tune the length of the salt (default: 16)
* `Argon2 Hash Length` --> tune the length of the hash (default: 32)

> I have deprecated use of the `Argon2 Max Time` provider, as I believe it offers no real value. If you still have a use-case for this, let me know.

For parameter optimization, check the [Argon2 whitepaper recommendations](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf#section.9).
