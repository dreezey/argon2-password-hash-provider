#!/bin/bash

set -ex

docker run -it --rm --name argon2-password-hash-provider -v "$(pwd)":/usr/src/mymaven -w /usr/src/mymaven maven:3.3-jdk-8 mvn clean package
echo "cp target/argon2-password-hash-provider-2.0.1.jar [your]/keycloak/deployments/"
#cp target/argon2-password-hash-provider-2.0.1.jar ../../../../dxp-services/keycloak/deployments/
