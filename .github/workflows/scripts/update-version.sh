#!/bin/bash -xe

MINOR_VERSION=$(
  sed -n 's|^    <version>[0-9]\+\.[0-9]\+\.\([0-9]\+\)-SNAPSHOT</version>|\1|p' pom.xml
)
echo ${MINOR_VERSION}
MINOR_VERSION=$((++MINOR_VERSION))
echo ${MINOR_VERSION}

# update version in pom.xml
sed -i \
 "s|^\(    <version>[0-9]\+\.[0-9]\+\.\)[0-9]\+-SNAPSHOT\(</version>\)|\1${MINOR_VERSION}-SNAPSHOT\2|" \
 pom.xml

if [ "${COMPONENT}" = "personium-lib-common" ]; then
  exit 0
fi

# update version in personium-unit-config-default.properties
sed -i \
  "s|^\(io\.personium\.core\.version=[0-9]\+\.[0-9]\+\.\)[0-9]\+|\1${MINOR_VERSION}|" \
  src/main/resources/personium-unit-config-default.properties
  