/**
 * personium.io
 * Copyright 2014 FUJITSU LIMITED
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
import org.slf4j.LoggerFactory;;

/**
 * class for creating and parsing grant code.
 */
public class GrantCode extends AbstractLocalAccessToken implements IAccessToken {

    /**
     * Logger.
     */
    static Logger log = LoggerFactory.getLogger(GrantCode.class);


    @Override
    int getType() {
        return AbstractLocalToken.Type.GRANT_CODE;
    }

    /** prefix of code. */
    public static final String PREFIX_CODE = "GC~";


    /** Code valid time (ms). */
    public static final int CODE_EXPIRES = 10 * 60 * 1000; // 10 minuts


    public GrantCode() {
    }
    /**
     * Constructor for generating code.
     * @param issuedAt issuedAt
     * @param lifespan lifespan
     * @param issuer issuer
     * @param subject subject
     * @param roleList roleList
     * @param schema schema
     * @param scope scope
     */
    public GrantCode(final long issuedAt,
            final long lifespan,
            final String issuer,
            final String subject,
            final List<Role> roleList,
            final String schema,
            final String scope) {
        super(issuedAt, lifespan, issuer, subject, schema, scope);
        if (roleList != null) {
            this.roleList = roleList;
        }
    }

    /**
     * 明示的な有効期間を設定してトークンを生成する.
     * @param issuedAt 発行時刻(epochからのミリ秒)
     * @param lifespan トークンの有効時間（ミリ秒）
     * @param issuer 発行 Cell URL
     * @param subject アクセス主体URL
     * @param roleList ロールリスト
     * @param schema クライアント認証されたデータスキーマ
     */
    public GrantCode(final long issuedAt,
            final long lifespan,
            final String issuer,
            final String subject,
            final List<Role> roleList,
            final String schema) {
        this(issuedAt, lifespan, issuer, subject, roleList, schema, null);
    }

    /**
     * 既定値の有効期間を設定してトークンを生成する.
     * @param issuedAt 発行時刻(epochからのミリ秒)
     * @param issuer 発行 Cell URL
     * @param subject アクセス主体URL
     * @param roleList ロールリスト
     * @param schema クライアント認証されたデータスキーマ
     */
    public GrantCode(
            final long issuedAt,
            final String issuer,
            final String subject,
            final List<Role> roleList,
            final String schema) {
        this(issuedAt, ACCESS_TOKEN_EXPIRES_MILLISECS, issuer, subject, roleList, schema);
    }

    /**
     * 既定値の有効期間と現在を発行日時と設定してトークンを生成する.
     * @param issuer 発行 Cell URL
     * @param subject アクセス主体URL
     * @param roleList ロールリスト
     * @param schema クライアント認証されたデータスキーマ
     */
    public GrantCode(final String issuer, final String subject,
            final List<Role> roleList, final String schema) {
        this(new DateTime().getMillis(), issuer, subject, roleList, schema);
    }

    /**
     * Create code string and return.
     * @return code string
     */
    public String toTokenString() {
        StringBuilder ret = new StringBuilder(PREFIX_CODE);
        ret.append(doCreateTokenString(null));
        return ret.toString();
    }


    /**
     * Parse code string to token.
     * @param code code string
     * @param issuer issuer
     * @return Parsed token
     * @throws AbstractOAuth2Token.TokenParseException parse error
     */
    public static GrantCode parse(String code, String issuer)
            throws AbstractOAuth2Token.TokenParseException {
        if (!code.startsWith(PREFIX_CODE) || issuer == null) {
            throw AbstractOAuth2Token.PARSE_EXCEPTION;
        }

        GrantCode ret = new GrantCode();
        ret.populate(code.substring(PREFIX_CODE.length()), issuer, 0);
//      ret.roleList = AbstractOAuth2Token.parseRolesString(ext[0]);

        return ret;
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
