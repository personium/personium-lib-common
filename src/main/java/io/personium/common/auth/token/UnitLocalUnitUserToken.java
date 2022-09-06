/**
 * Personium
 * Copyright 2019-2022 Personium Project Authors
 * - Akio Shimono
 * - FUJITSU LIMITED
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.personium.common.auth.token;

/**
 * class for creating / parsing Unit Local Unit User Token.
 */
public class UnitLocalUnitUserToken extends AbstractLocalAccessToken {

    /**
     * Token Prefix.
     */
    public static final String PREFIX_UNIT_LOCAL_UNIT_USER = "AU~";
    @Override
    int getType() {
        return AbstractLocalToken.Type.AccessToken.UNIT_LOCLAL_UNIT_USER;
    }

    /**
     * Default constructor.
     */
    public UnitLocalUnitUserToken() {
    }

    /**
     * Constructor.
     * @param issuedAt token issue time (millisec from the epoch)
     * @param lifespan token lifespan (in millisec)
     * @param subject Unit user name
     * @param issuer Issuer (Unit domain name)
     */
    public UnitLocalUnitUserToken(final long issuedAt, final long lifespan, final String subject, final String issuer) {
        this.issuedAt = issuedAt;
        this.lifespan = lifespan;
        this.subject = subject;
        this.issuer = issuer;
    }

    /**
     * parse a token string as a Cell specified with the issuer parameter.
     * @param token Token String
     * @param issuer Cell Root URL
     * @return UnitLocalUnitUserToken object
     * @throws AbstractOAuth2Token.TokenParseException when failed to parse the string
     */
    public static UnitLocalUnitUserToken parse(final String token, final String issuer)
            throws AbstractOAuth2Token.TokenParseException {
        if (!token.startsWith(PREFIX_UNIT_LOCAL_UNIT_USER) || issuer == null) {
            throw AbstractOAuth2Token.PARSE_EXCEPTION;
        }
        UnitLocalUnitUserToken ret = new UnitLocalUnitUserToken();
        ret.populate(token.substring(PREFIX_UNIT_LOCAL_UNIT_USER.length()), issuer, 0);
        return ret;
    }

    @Override
    public String toTokenString() {
        StringBuilder ret = new StringBuilder(PREFIX_UNIT_LOCAL_UNIT_USER);
        ret.append(this.doCreateTokenString(null));
        return ret.toString();
    }

    @Override
    public String getTarget() {
        return null;
    }

    @Override
    public String getId() {
        return this.subject + ":" + this.issuedAt;
    }

}
