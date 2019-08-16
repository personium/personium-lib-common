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
 * Class for creating and parsing Cell Local Refresh Token.
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
     * 明示的な有効期間を設定してトークンを生成する.
     * @param issuedAt 発行時刻(epochからのミリ秒)
     * @param lifespan トークンの有効時間（ミリ秒）
     * @param issuer 発行 Cell URL
     * @param subject アクセス主体URL
     * @param schema クライアント認証されたデータスキーマ
     */
    public ResidentRefreshToken(
            final long issuedAt,
            final long lifespan,
            final String issuer,
            final String subject,
            final String schema,
            final String scope) {
        super(issuedAt, lifespan, issuer, subject, schema, scope);
    }

    /**
     * 既定値の有効期間を設定してトークンを生成する.
     * @param issuedAt 発行時刻(epochからのミリ秒)
     * @param issuer 発行 Cell URL
     * @param subject アクセス主体URL
     * @param schema クライアント認証されたデータスキーマ
     */
    public ResidentRefreshToken(
            final long issuedAt,
            final String issuer,
            final String subject,
            final String schema,
            final String scope) {
        this(issuedAt, REFRESH_TOKEN_EXPIRES_MILLISECS, issuer, subject, schema, scope);
    }

    /**
     * Constructor.
     * 既定値の有効期間と現在を発行日時と設定してトークンを生成する.
     * @param issuer 発行 Cell URL
     * @param subject アクセス主体URL
     * @param schema クライアント認証されたデータスキーマ
     */
    public ResidentRefreshToken(final String issuer, final String subject, final String schema, String scope) {
        this(new DateTime().getMillis(), issuer, subject, schema, scope);
    }

    @Override
    public String toTokenString() {
        StringBuilder ret = new StringBuilder(PREFIX_REFRESH);
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
            // 自分セルローカル払い出し時に払い出されるリフレッシュトークンにはロール入ってないので取得する。
            return new TransCellAccessToken(issuedAt, lifespan, this.issuer, cellUrl + "#" + this.getSubject(),
                    target, roleList, schema);
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
