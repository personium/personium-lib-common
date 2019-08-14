/**
 * Personium
 * Copyright 2019 Personium Project
 *  - Fujitsu Ltd.
 *  - (Add authors here)
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
 * Account Access Token の生成・パースを行うクラス.
 */
public final class AccountAccessToken extends AbstractLocalAccessToken implements IAccessToken {

    /**
     * Logger.
     */
    static Logger log = LoggerFactory.getLogger(AccountAccessToken.class);

    /**
     * Token PREFIX String.
     */
    public static final String PREFIX_ACCESS = "AA~";

    /**
     * Token Type String.
     */
    @Override
    int getType() {
        return AbstractLocalToken.Type.AccessToken.SELF_LOCAL;
    }


    public AccountAccessToken() {
    }


    /**
     * 明示的な有効期間を設定してトークンを生成する.
     * @param issuedAt 発行時刻(epochからのミリ秒)
     * @param lifespan 有効期間(ミリ秒)
     * @param issuer 発行者
     * @param subject Subject
     * @param schema Schema
     */
    public AccountAccessToken(final long issuedAt, final long lifespan, final String issuer,
            final String subject, final String schema, String scope) {
        super(issuedAt, lifespan, issuer, subject, schema, scope);
    }

    /**
     * 既定値の有効期間を設定してトークンを生成する.
     * @param issuedAt 発行時刻(epochからのミリ秒)
     * @param issuer 発行者
     * @param subject Subject
     * @param schema Schema
     */
    public AccountAccessToken(final long issuedAt, final String issuer, final String subject, final String schema, String scope) {
        this(issuedAt, ACCESS_TOKEN_EXPIRES_MILLISECS, issuer, subject, schema, scope);
    }

    @Override
    public String toTokenString() {
        StringBuilder ret = new StringBuilder(PREFIX_ACCESS);
        ret.append(this.doCreateTokenString(null));
        return ret.toString();
    }

    /**
     * トークン文字列をissuerで指定されたCellとしてパースする.
     * @param token Token String
     * @param issuer Cell Root URL
     * @return パースされたCellLocalTokenオブジェクト
     * @throws AbstractOAuth2Token.TokenParseException トークンのパースに失敗したとき投げられる例外
     */
    public static AccountAccessToken parse(final String token, final String issuer)
            throws AbstractOAuth2Token.TokenParseException {
        if (!token.startsWith(PREFIX_ACCESS) || issuer == null) {
            throw AbstractOAuth2Token.PARSE_EXCEPTION;
        }
        AccountAccessToken ret = new AccountAccessToken();
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
