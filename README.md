# Dependencies
This module depends on `de.mkammerer.argon2`, more can be found on the [GitHub Project](https://github.com/phxql/argon2-jvm).

## Dependency installation
Build the project once with `mvn install`, this will generate the `target/lib/` directory, with two dependencies:
* argon2-jvm-*.jar
* jna-*.jar

In your Keycloak installation, go to `modules/system/layers/base` and create the following new directories:
```
mkdir -p ./modules/system/layers/base/de/mkammerer/argon2/main/;
mkdir -p ./modules/system/layers/base/com/sun/jna/main/;
```

### Argon2
For the Argon2 dependency, copy the `*.jar` file into the module directory, and create the following `module.xml`:
```
<?xml version="1.0" encoding="UTF-8"?>
<module name="de.mkammerer.argon2" xmlns="urn:jboss:module:1.7">

    <properties>
        <property name="jboss.api" value="private"/>
    </properties>

    <resources>
        <resource-root path="argon2-jvm-2.6.jar"/>
    </resources>

    <dependencies>
        <module name="com.sun.jna"/>
    </dependencies>
</module>
```

### JNA
Like Argon2, copy the `*.jar` file into the module directory, and create the following `module.xml`:
```
<?xml version="1.0" encoding="UTF-8"?>
<module name="com.sun.jna" xmlns="urn:jboss:module:1.7">

    <properties>
        <property name="jboss.api" value="private"/>
    </properties>

    <resources>
        <resource-root path="jna-4.1.0.jar"/>
    </resources>
</module>
```

# Module deployment
Once the dependencies are in order, you can deploy the module either via the `modules` directory, or hot deployment.

# Keycloak configuration
Finally, in the Keycloak realm of your choosing, activate the Argon2 password hashing via:
`Authentication > Password Policy` and then selecting the policy `Hashing Algorithm` and name it: `argon2`.

Further tuning can be done by the other Policy Providers:
* `Argon2 Variant` --> you can choose which Argon2 variant to use, either: ARGON2i, ARGON2d or ARGON2id
* `Argon2 Iterations` --> tune the number of iterations the provider will perform
* `Argon2 Memory Usage` --> tune the memory limitation of the provider
* `Argon2 Paralellism` --> tune the number of threads and memory lanes
* `Argon2 Salt Length` --> tune the length of the salt
* `Argon2 Hash Length` --> tune the length of the hash

For security purposes, there's also the possibility to configure the maximum runtime of the hashing, by default it's 1000 milliseconds, however it can be configured via the `Argon2 Max Time` policy.
In case the hashing exceeds this time, it will generate a `WARN` in the console.

For parameter optimization, check the [project's benchmark](https://github.com/phxql/argon2-jvm#recommended-parameters) or the [Argon2 whitepaper recommendations](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf#section.9).