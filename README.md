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

Important next step is to change the iterations, select the policy `Hashing Iterations` and change it to either `1` or `2`.
Or perform the benchmark on your system using the [project's benchmark](https://github.com/phxql/argon2-jvm#recommended-parameters).