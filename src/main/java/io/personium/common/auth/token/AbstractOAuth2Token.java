/**
 * Personium
 * Copyright 2019 Personium Project
 * - FUJITSU LIMITED
 * - (Add Authors here)
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
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;



/**
 * base abstract class for various Token classes defined in this package.
 */
public abstract class AbstractOAuth2Token {
    /**
     * Milliseconds in a second. 1000
     */
    public static final int MILLISECS_IN_A_SEC = 1000;
    /**
     * Seconds in an hour. 3600
     */
    public static final int SECS_IN_AN_HOUR = 60 * 60;
    /**
     * Millisec in an hour. 3600000
     */
    public static final int MILLISECS_IN_AN_HOUR = SECS_IN_AN_HOUR * MILLISECS_IN_A_SEC;
    /**
     * Seconds in a day.
     */
    public static final int SECS_IN_A_DAY = 24 * SECS_IN_AN_HOUR;

    /** access token expires hour. */
    public static final int ACCESS_TOKEN_EXPIRES_HOUR = 1;
    /** access token expires millisecs. */
    public static final long ACCESS_TOKEN_EXPIRES_MILLISECS = ACCESS_TOKEN_EXPIRES_HOUR * MILLISECS_IN_AN_HOUR;
    /** refresh token expires hour.  */
    public static final int REFRESH_TOKEN_EXPIRES_HOUR = 24;
    /** refresh token expires millisecs.  */
    public static final long REFRESH_TOKEN_EXPIRES_MILLISECS = REFRESH_TOKEN_EXPIRES_HOUR * MILLISECS_IN_AN_HOUR;

    /**
     * Token parse Exception class.
     */
    @SuppressWarnings("serial")
    public static class TokenParseException extends Exception {
        /**
         * Constructor.
         * @param msg message
         */
        public TokenParseException(final String msg) {
            super(msg);
        }
        /**
         * Constructor.
         * @param e cause Throwable
         */
        public TokenParseException(final Throwable e) {
            super(e);
        }
        /**
         * Constructor.
         * @param msg message
         * @param e cause Throwable
         */
        public TokenParseException(final String msg, final Throwable e) {
            super(msg, e);
        }
    }
    /**
     * Signature validation exception class.
     */
    @SuppressWarnings("serial")
    public static class TokenDsigException extends Exception {
        /**
         * Constructor.
         * @param msg message
         */
        public TokenDsigException(final String msg) {
            super(msg);
        }
        /**
         * Constructor.
         * @param e cause Throwable
         */
        public TokenDsigException(final Throwable e) {
            super(e);
        }
        /**
         * Constructor.
         * @param msg message
         * @param e cause Throwable
         */
        public TokenDsigException(final String msg, final Throwable e) {
            super(msg, e);
        }
    }
    /**
     * 本パッケージで用いるルートCA証明書例外クラス.
     */
    @SuppressWarnings("serial")
    public static class TokenRootCrtException extends Exception {
        /**
         * Constructor.
         * @param msg message
         */
        public TokenRootCrtException(final String msg) {
            super(msg);
        }
        /**
         * Constructor.
         * @param e cause Throwable
         */
        public TokenRootCrtException(final Throwable e) {
            super(e);
        }
        /**
         * Constructor.
         * @param msg message
         * @param e cause Throwable
         */
        public TokenRootCrtException(final String msg, final Throwable e) {
            super(msg, e);
        }
    }

    public static class Scope {
        public static final String[] ENGINE = new String[] {"root"};
        public static final String[] EMPTY = new String[0];

        /** openid. It is used with the openid connect of the oauth2 extension. */
        public static final String OPENID = "openid";

        public static String[] parse(String scopeValue) {
            if (scopeValue == null) {
                return new String[0];
            }
            String[] ret = scopeValue.split(" ");
            // TODO 空白があれば消したい。
            return ret;
        }
        public static String toConcatValue(String[] scope) {
            if (scope == null) {
                return "";
            }
            return StringUtils.join(scope, " ");
        }
    }

    long issuedAt;
    long lifespan;
    String issuer;
    String subject;
    String schema;
    List<Role> roleList = new ArrayList<Role>();
    String[] scope;

    /**
     * returns Token Issuer URL.
     * @return Token Issuer URL
     */
    public final String getIssuer() {
        return this.issuer;
    }

    /**
     * returns Token Subject URL.
     * @return Subject URL
     */
    public final String getSubject() {
        return this.subject;
    }

    /**
     * returns schema URL.
     * @return Schema Url
     */
    public final String getSchema() {
        return this.schema;
    }

    /**
     * Get scope.
     * @return scope
     */
    public String[] getScope() {
        return this.scope;
    }
    /**
     * returns Role List.
     * @return Role list
     */
    public final List<Role> getRoleList() {
        return this.roleList;
    }

    final void addRole(final Role role) {
        this.roleList.add(role);
    }

    final String makeRolesString() {
        if (this.roleList == null || this.roleList.size() == 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (Role rl : this.roleList) {
            sb.append(rl.createUrl());
            sb.append(" ");
        }
        return sb.substring(0, sb.length() - 1);
    }

    static List<Role> parseRolesString(final String rolesStr) throws MalformedURLException {
        List<Role> ret = new ArrayList<Role>();
        if ("".equals(rolesStr)) {
            return ret;
        }
        for (String s : rolesStr.split(" ")) {
            ret.add(new Role(new URL(s)));
        }
        return ret;
    }

    static final TokenParseException PARSE_EXCEPTION = new TokenParseException("failed to parse token");

    /**
     * Get the time when this token was issued.
     * @return integer timestamp of seconds
     */
    public final int getIssuedAt() {
        return (int) (this.issuedAt / MILLISECS_IN_A_SEC);
    }

    /**
     * Get the period that this token is active.
     * @return integer period of seconds
     */
    public final int expiresIn() {
        return (int) (this.lifespan / MILLISECS_IN_A_SEC);
    }

    /**
     * Check if this token is active.
     * @return boolean
     */
    public final boolean isExpired() {
        long now = new Date().getTime();

        long expiresLimit = this.issuedAt + this.lifespan;

        if (now > expiresLimit) {
            return true;
        }
        return false;
    }

    /**
     * Expiration time in second of Refresh token.
     * @return Expiration time in second
     */
    public final int refreshExpiresIn() {
        return expiresIn();
    }

    /**
     * Check if this token is active.
     * @return boolean
     */
    public final boolean isRefreshExpired() {
        return isExpired();
    }

    /**
     * トークン文字列をissuerで指定されたCellとしてパースする.
     * @param token Token String
     * @param issuer Cell Root URL
     * @param host リクエストヘッダHostの値
     * @return パースされたCellLocalTokenオブジェクト
     * @throws TokenParseException トークンのパースに失敗したときに投げられる例外
     * @throws TokenDsigException トークンの署名検証に失敗した時に投げられる例外
     * @throws TokenRootCrtException ルートCA証明書の検証に失敗した時に投げられる例外
     */
    public static AbstractOAuth2Token parse(final String token, final String issuer, final String host)
            throws TokenParseException, TokenDsigException, TokenRootCrtException {
        if (token.startsWith(ResidentLocalAccessToken.PREFIX_ACCESS)) {
            return ResidentLocalAccessToken.parse(token, issuer);
        } else if (token.startsWith(PasswordChangeAccessToken.PREFIX_ACCESS)) {
            return PasswordChangeAccessToken.parse(token, issuer);
        } else if (token.startsWith(VisitorLocalAccessToken.PREFIX_ACCESS)) {
            return VisitorLocalAccessToken.parse(token, issuer);
        } else if (token.startsWith(ResidentRefreshToken.PREFIX_REFRESH)) {
            return ResidentRefreshToken.parse(token, issuer);
        } else if (token.startsWith(VisitorRefreshToken.PREFIX_TC_REFRESH)) {
            return VisitorRefreshToken.parse(token, issuer);
        } else if (token.startsWith(UnitLocalUnitUserToken.PREFIX_UNIT_LOCAL_UNIT_USER)) {
            return UnitLocalUnitUserToken.parse(token, host);
        } else if (token.startsWith(GrantCode.PREFIX_CODE)) {
            return GrantCode.parse(token, issuer);
        } else {
            return TransCellAccessToken.parse(token);
        }
    }

    final String toDebugStr() {
        Map<String, String> map = new HashMap<String, String>();
        map.put("issuedAt", new Date(this.issuedAt).toString());
        map.put("expiresAt", new Date(this.issuedAt + this.lifespan).toString());
        map.put("issuer", this.issuer);
        map.put("subject", this.subject);
        map.put("schema", this.schema);
        if (this.makeRolesString() != null) {
            map.put("roles", this.makeRolesString());
        }
        return map.toString();
    }
}
