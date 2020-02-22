# Introduction
This project introduces Argon2 Password Hashing for Keycloak, it uses `de.mkammerer.argon2` as the library, more can be found on the [GitHub Project](https://github.com/phxql/argon2-jvm).

It generates an EAR which can be deployed using [Keycloak Deployer](https://www.keycloak.org/docs/latest/server_development/index.html#using-the-keycloak-deployer). 

# Build
Build the project using:
```
mvn clean install;
```

This will build both the `jar-module` and `ear-module`:
```
[INFO] Reactor Summary for Argon2 Password Hash Provider 9.0.0:
[INFO] 
[INFO] Argon2 Password Hash Provider ...................... SUCCESS [  0.633 s]
[INFO] Argon2 Password Hash Provider Module ............... SUCCESS [  3.264 s]
[INFO] Argon2 Password Hash Provider Bundle ............... SUCCESS [  0.348 s]
```

# Installation
The EAR will contain all the necessary dependencies, therefore you can hot-deploy the module without additional configuration:
```
cp ear-module/target/argon2-password-hash-provider-bundle-9.0.0.ear /opt/keycloak/standalone/deployments/;
```

# System Dependencies
When running Keycloak on CentOS 7 (or another EL7), install argon2 system library:
```
yum install -y epel-release;
yum install -y argon2;
```

Once this is complete, start Keycloak.

# Keycloak configuration
Finally, in the Keycloak realm of your choosing, activate the Argon2 password hashing via:
`Authentication > Password Policy` and then selecting the policy `Hashing Algorithm` and name it: `argon2`.

Further tuning can be done by the other Policy Providers:
* `Argon2 Variant` --> you can choose which Argon2 variant to use, either: ARGON2i, ARGON2d or ARGON2id
* `Argon2 Iterations` --> tune the number of iterations the provider will perform
* `Argon2 Memory Usage` --> tune the memory limitation of the provider
* `Argon2 Parallelism` --> tune the number of threads and memory lanes
* `Argon2 Salt Length` --> tune the length of the salt
* `Argon2 Hash Length` --> tune the length of the hash

For security purposes, there's also the possibility to configure the desired maximum runtime of the hashing, by default it's 1000 milliseconds, however it can be configured via the `Argon2 Max Time` policy.
In case the hashing exceeds this time, it will generate a `WARN` in the console.

For parameter optimization, check the [project's benchmark](https://github.com/phxql/argon2-jvm#recommended-parameters) or the [Argon2 whitepaper recommendations](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf#section.9).
