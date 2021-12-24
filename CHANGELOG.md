## 1.5.4
IMPROVEMENTS:
* Update pom.xml for releasing to Maven central repository

## 1.5.3
BREAKING CHANGES:
* Bytes used for CBC Initial Vector in Local Token encryption changed. ([#73](https://github.com/personium/personium-lib-common/issues/73))
* Role URLs in TransCellAccessToken / VisitorRefeshToken are now role class URLs. (Role URLs in VisitorLocalAccessToken are role instance URLs)

BUG FIXES:
* Role Url in TransCellAccessToken sometimes not preserved with parsing process. ([#70](https://github.com/personium/personium-lib-common/issues/70))
* Common.setFQDN does not work when FQDN is already set.

## 1.5.2
BREAKING CHANGES:
* All classes are put under io.personium.common.*


