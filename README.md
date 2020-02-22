# Dependencies
This module depends on `de.mkammerer.argon2`, more can be found on the [GitHub Project](https://github.com/phxql/argon2-jvm).

## Dependency installation
Build the project once with `mvn install`, this will generate the `./target/jboss-modules/` directory, with two dependencies:
* de.mkammerer.argon2-jvm
* net.java.dev.jna

In your Keycloak installation, go to `./modules/` and modify the `layers.conf`:
```
layers=keycloak,custom
```

And create the directory in `./modules/`:
```
mkdir -p ./modules/system/layers/custom;
```

Now simply copy the 2 dependencies (generated in `./target/jboss-modules`) folders into the `custom` directory in Keycloak modules, e.g.:
```
cp -R ./target/jboss-modules/de ./target/jboss-modules/net /opt/keycloak/modules/system/layers/custom/;
```

# System Dependencies
When running Keycloak on CentOS 7 (or another EL7), install argon2 system library:
```
yum install -y epel-release;
yum install -y argon2;
```

Once this is complete, restart Keycloak.

# Provider deployment
Once the dependencies are in order, the provider can be deployed by the [Keycloak Deployer](https://www.keycloak.org/docs/latest/server_development/index.html#using-the-keycloak-deployer), e.g.:
```
cp ./target/argon2-password-hash-provider-9.0.0.jar /opt/keycloak/standalone/deployments/;
```

Keycloak will then load the provider when started (it also supports hot-deployments).

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
