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

import java.net.MalformedURLException;
import java.util.List;
import java.util.UUID;

import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Class to handle refresh token that is issued via Trans Cell Access Token assertion.
 */
public final class VisitorRefreshToken extends AbstractLocalToken implements IRefreshToken, IExtRoleContainingToken {

    /**
     * Logger.
     */
    static Logger log = LoggerFactory.getLogger(VisitorRefreshToken.class);

    /**
     * Token prefix.
     */
    public static final String PREFIX_TC_REFRESH = "RV~";

    /**
     * Token Type String.
     */
    @Override
    int getType() {
        return AbstractLocalToken.Type.RefreshToken.VISITOR;
    }

    static final int IDX_ID = 0;
    static final int IDX_ORIG_ISSUER = 1;
    static final int IDX_ORIG_ROLE_LIST = 2;

    static final int COUNT_IDX_EXTRA = 3;

    String id;
    String originalIssuer;

    /**
     * Default constructor.
     */
    public VisitorRefreshToken() {
    }

    /**
     * Constructor.
     * @param id Token id
     * @param issuedAt time this token is issued (millisec from the epoch)
     * @param lifespan token lifespan (in millisec)
     * @param issuer issuer Cell URL
     * @param subject access subject url
     * @param origIssuer original TransCellAccessToken issuer used when this token is issued
     * @param origRoleList Role list in the original TransCellAccessToken used to issue this token
     * @param schema client-authenticated data schema
     * @param scope scopes in the form of String array
     */
    public VisitorRefreshToken(
            final String id,
            final long issuedAt,
            final long lifespan,
            final String issuer,
            final String subject,
            final String origIssuer,
            final List<Role> origRoleList,
            final String schema,
            final String[] scope) {
        super(issuedAt, lifespan, issuer, subject, schema, scope);
        this.id = id;
        this.originalIssuer = origIssuer;
        this.roleList = origRoleList;
    }

    /**
     * @deprecated use other constructor.
     * @param id Token id
     * @param issuedAt time this token is issued (millisec from the epoch)
     * @param issuer issuer Cell URL
     * @param subject subject URL
     * @param origIssuer original TransCellAccessToken issuer used when this token is issued
     * @param origRoleList Role list in the original TransCellAccessToken used to issue this token
     * @param schema client-authenticated data schema
     * @param scope scopes in the form of String array
     */
    public VisitorRefreshToken(
            final String id,
            final long issuedAt,
            final String issuer,
            final String subject,
            final String origIssuer,
            final List<Role> origRoleList,
            final String schema,
            final String[] scope) {
        this(id, issuedAt, REFRESH_TOKEN_EXPIRES_MILLISECS,
                issuer, subject, origIssuer, origRoleList, schema, scope);
    }

    /**
     * @deprecated use other constructor.
     * @param id Token id
     * @param issuer issuer Cell URL
     * @param subject subject URL
     * @param origIssuer original TransCellAccessToken issuer used when this token is issued
     * @param origRoleList Role list in the original TransCellAccessToken used to issue this token
     * @param schema client-authenticated data schema
     * @param scope scopes in the form of String array
     */
    public VisitorRefreshToken(
            final String id,
            final String issuer,
            final String subject,
            final String origIssuer,
            final List<Role> origRoleList,
            final String schema,
            final String[] scope) {
        this(id, new DateTime().getMillis(), issuer, subject, origIssuer, origRoleList, schema, scope);
    }

    @Override
    public String toTokenString() {
        StringBuilder ret = new StringBuilder(PREFIX_TC_REFRESH);
        String[] items = new String[] {this.id, this.originalIssuer, this.makeRolesString()};
        ret.append(this.doCreateTokenString(items));
        return ret.toString();
    }

    /**
     * parse a given token string as a Cell specified with the issuer parameter.
     * @param token Token String
     * @param issuer Cell Root URL
     * @return VisitorRefreshToken object as a parse result
     * @throws AbstractOAuth2Token.TokenParseException when failed to parse the string
     */
    public static VisitorRefreshToken parse(final String token, final String issuer)
            throws AbstractOAuth2Token.TokenParseException {
        if (!token.startsWith(PREFIX_TC_REFRESH) || issuer == null) {
            throw AbstractOAuth2Token.PARSE_EXCEPTION;
        }

        VisitorRefreshToken ret = new VisitorRefreshToken();

        try {
            String[] extra = ret.populate(token.substring(PREFIX_TC_REFRESH.length()), issuer, COUNT_IDX_EXTRA);
            ret.id = extra[IDX_ID];
            ret.originalIssuer = extra[IDX_ORIG_ISSUER];
            // Role class url list is there in Visitor Refresh Tokens
            ret.roleList = AbstractOAuth2Token.parseSpaceSeparatedRoleClassUrlString(extra[IDX_ORIG_ROLE_LIST]);
            return ret;
        } catch (MalformedURLException e) {
            throw new TokenParseException("failed to parse token", e);
        }
    }

    @Override
    public String getId() {
        return this.id;
    }

    /**
     * {@inheritDoc}
     * @deprecated
     */
    @Override
    public IAccessToken refreshAccessToken(final long issuedAt, final String target, String url, List<Role> role) {
        return refreshAccessToken(issuedAt, ACCESS_TOKEN_EXPIRES_MILLISECS, target, url, role);
    }



    /**
     * {@inheritDoc}
     */
    @Override
    public IAccessToken refreshAccessToken(final long issuedAt, final long lifespan, final String target, String url,
            List<Role> role) {
        if (target == null) {
            return new VisitorLocalAccessToken(issuedAt, lifespan, url, this.getSubject(), role, schema, scope);
        } else {
            return new TransCellAccessToken(issuedAt, lifespan, url, this.getSubject(), target, role, schema, scope);
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
        // TODO Should reload RoleList info.
        return new VisitorRefreshToken(UUID.randomUUID().toString(), issuedAt, lifespan, this.issuer, this.subject,
                this.originalIssuer, this.getRoleList(), this.schema, this.scope);
    }


    @Override
    public String getExtCellUrl() {
        return this.originalIssuer;
    }
    /**
     * {@inheritDoc}
     */
    @Override
    String makeRolesString() {
        return makeRoleClassUrlListString();
    }
}
