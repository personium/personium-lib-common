/**
 * Personium
 * Copyright 2014-2022 Personium Project Authors
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


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class for creating / parsing non-Trans-cell access token issued at and for the account subjects on the local cell.
 * old name: AccountAccessToken.
 */
public final class ResidentLocalAccessToken extends AbstractLocalAccessToken {

    /**
     * Logger.
     */
    static Logger log = LoggerFactory.getLogger(ResidentLocalAccessToken.class);

    /**
     * Token PREFIX String.
     */
    public static final String PREFIX_ACCESS = "AR~";

    /**
     * Token Type String.
     */
    @Override
    int getType() {
        return AbstractLocalToken.Type.AccessToken.SELF_LOCAL;
    }


    public ResidentLocalAccessToken() {
    }


    /**
     * Constructor.
     * @param issuedAt the time token is issued (millisec from the epoch)
     * @param lifespan Token lifespan (Millisec)
     * @param issuer Issuer
     * @param subject Subject
     * @param schema Schema
     * @param scopes Scopes in the form of String array
     */
    public ResidentLocalAccessToken(final long issuedAt, final long lifespan, final String issuer,
            final String subject, final String schema, String[] scopes) {
        super(issuedAt, lifespan, issuer, subject, schema, scopes);
    }

    /**
     * Constructor.
     * @param issuedAt the time token is issued (millisec from the epoch)
     * @param issuer Issuer
     * @param subject Subject (account name)
     * @param schema Schema
     * @param scopes scopes in the form of String array
     */
    public ResidentLocalAccessToken(final long issuedAt,
            final String issuer,
            final String subject,
            final String schema,
            String[] scopes) {
        this(issuedAt, ACCESS_TOKEN_EXPIRES_MILLISECS, issuer, subject, schema, scopes);
    }

    @Override
    public String toTokenString() {
        StringBuilder ret = new StringBuilder(PREFIX_ACCESS);
        ret.append(this.doCreateTokenString(null));
        return ret.toString();
    }

    /**
     * parse a given token string as a Cell specified with the issuer parameter.
     * @param token Token String
     * @param issuer Cell Root URL
     * @return parsed CellLocalToken object
     * @throws AbstractOAuth2Token.TokenParseException when failed to parse the string
     */
    public static ResidentLocalAccessToken parse(final String token, final String issuer)
            throws AbstractOAuth2Token.TokenParseException {
        if (!token.startsWith(PREFIX_ACCESS) || issuer == null) {
            throw AbstractOAuth2Token.PARSE_EXCEPTION;
        }
        ResidentLocalAccessToken ret = new ResidentLocalAccessToken();
        ret.populate(token.substring(PREFIX_ACCESS.length()), issuer, 0);
        return ret;
    }

    @Override
    public String getId() {
        return this.issuer + ":" + this.issuedAt;
    }

    @Override
    public String getTarget() {
        return this.issuer;
    }
}
