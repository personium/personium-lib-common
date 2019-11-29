/**
 * Personium
 * Copyright 2019 Personium Project Authors
 *  - Akio Shimono
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
public class UnitLocalUnitUserToken extends AbstractLocalAccessToken implements IAccessToken {

    /**
     * Token Prefix.
     */
    public static final String PREFIX_UNIT_LOCAL_UNIT_USER = "AU~";
    @Override
    int getType() {
        return AbstractLocalToken.Type.AccessToken.UNIT_LOCLAL_UNIT_USER;
    }

    /**
     * Default constructor
     */
    public UnitLocalUnitUserToken() {
    }

    /**
     * 明示的な有効期間を設定してトークンを生成する.
     * @param issuedAt 発行時刻(epochからのミリ秒)
     * @param lifespan 有効時間(ミリ秒)
     * @param subject ユニットユーザ名
     * @param issuer 発行者(自ホスト名)
     */
    public UnitLocalUnitUserToken(final long issuedAt, final long lifespan, final String subject, final String issuer) {
        this.issuedAt = issuedAt;
        this.lifespan = lifespan;
        this.subject = subject;
        this.issuer = issuer;
    }

    /**
     * トークン文字列をissuerで指定されたCellとしてパースする.
     * @param token Token String
     * @param issuer Cell Root URL
     * @return パースされたCellLocalTokenオブジェクト
     * @throws AbstractOAuth2Token.TokenParseException トークンのパースに失敗したとき投げられる例外
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
