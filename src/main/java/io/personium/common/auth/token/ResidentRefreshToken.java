/**
 * Personium
 * Copyright 2019 Personium Project
 *  - FUJITSU LIMITED
 *  - (Add Authors here)
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

import java.util.List;

import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Class for creating and parsing RefreshToken issued for resident subject (subject authenticated at this local cell).
 * (old name Cell Local Refresh Token).
 *
 */
public final class ResidentRefreshToken extends AbstractLocalToken implements IRefreshToken {

    /**
     * Logger.
     */
    static Logger log = LoggerFactory.getLogger(ResidentRefreshToken.class);

    /**
     * Token Prefix for this token.
     */
    public static final String PREFIX_REFRESH = "RR~";

    @Override
    int getType() {
        return AbstractLocalToken.Type.RefreshToken.RESIDENT;
    }

    /**
     * Default Constructor.
     */
    public ResidentRefreshToken() {
    }

    /**
     * Constructor.
     * @param issuedAt token issue time (millisec from the epoch)
     * @param lifespan Token lifespan (Millisec)
     * @param issuer issuer Cell URL
     * @param subject access subject url
     * @param schema client-authenticated data schema
     * @param scopes Scopes in the form of String array
     */
    public ResidentRefreshToken(
            final long issuedAt,
            final long lifespan,
            final String issuer,
            final String subject,
            final String schema,
            final String[] scopes) {
        super(issuedAt, lifespan, issuer, subject, schema, scopes);
    }

    /**
     * Constructor.
     * @param issuedAt token issue time (millisec from the epoch)
     * @param issuer issuer Cell URL
     * @param subject access subject url
     * @param schema client-authenticated data schema
     * @param scopes Scopes in the form of String array
     */
    public ResidentRefreshToken(
            final long issuedAt,
            final String issuer,
            final String subject,
            final String schema,
            final String[] scopes) {
        this(issuedAt, REFRESH_TOKEN_EXPIRES_MILLISECS, issuer, subject, schema, scopes);
    }

    /**
     * Constructor.
     * @param issuer issuer Cell URL
     * @param subject access subject url
     * @param schema client-authenticated data schema
     * @param scopes scopes in the form of String array
     */
    public ResidentRefreshToken(final String issuer, final String subject, final String schema, String[] scopes) {
        this(new DateTime().getMillis(), issuer, subject, schema, scopes);
    }

    @Override
    public String toTokenString() {
        StringBuilder ret = new StringBuilder(PREFIX_REFRESH);
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
    public static ResidentRefreshToken parse(final String token, final String issuer)
            throws AbstractOAuth2Token.TokenParseException {
        if (!token.startsWith(PREFIX_REFRESH) || issuer == null) {
            throw AbstractOAuth2Token.PARSE_EXCEPTION;
        }
        ResidentRefreshToken ret = new ResidentRefreshToken();
        ret.populate(token.substring(PREFIX_REFRESH.length()), issuer, 0);
        return ret;
    }

    @Override
    public String getId() {
        return this.subject + this.issuedAt;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public IAccessToken refreshAccessToken(final long issuedAt,
            final String target, final String cellUrl, List<Role> roleList) {
        return refreshAccessToken(issuedAt, ACCESS_TOKEN_EXPIRES_MILLISECS, target, cellUrl, roleList);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public IAccessToken refreshAccessToken(final long issuedAt, final long lifespan,
            final String target, final String cellUrl, List<Role> roleList) {
        if (schema == null) {
            schema = this.getSchema();
        }
        if (target == null) {
            return new ResidentLocalAccessToken(issuedAt, lifespan, this.issuer, this.getSubject(), schema, scope);
        } else {
            // obtain and put role info in the token
            // since resident refresh tokens do not contain it.
            return new TransCellAccessToken(issuedAt, lifespan, this.issuer, cellUrl + "#" + this.getSubject(),
                    target, roleList, schema, scope);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public IRefreshToken refreshRefreshToken(final long issuedAt) {
        return refreshRefreshToken(issuedAt, REFRESH_TOKEN_EXPIRES_MILLISECS);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public IRefreshToken refreshRefreshToken(final long issuedAt, final long lifespan) {
        return new ResidentRefreshToken(issuedAt, lifespan, this.issuer, this.subject, this.schema, this.scope);
    }
}
