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


/**
 *  Interface class of OAuth2.0 refresh token used by Personium.
 */
public interface IRefreshToken {
    /**
     * getter of ID.
     * @return ID String
     */
    String getId();

    /**
     * Returning Schema URL, equivalent to OAuth2.0 Client ID.
     * @return Schema URL
     */
    String getSchema();

    /**
     * Return Subject string.
     * @return Subject string
     */
    String getSubject();

    /**
     * Return token string.
     * @return token string
     */
    String toTokenString();

    /**
     * Refresh to new Access Token with old refresh token.
     * @param issuedAt Issued time stamp
     * @param target Target cell URL
     * @param cellUrl Issuer cell URL
     * @param roleList List of roles
     * @return Access token
     */
    IAccessToken refreshAccessToken(long issuedAt, String target, String cellUrl,
            List<Role> roleList);

    /**
     * Refresh to new Access Token with old refresh token.
     * @param issuedAt Issued time stamp
     * @param target Target cell URL
     * @param cellUrl Issuer cell URL
     * @param roleList List of roles
     * @param schema Schema URI
     * @return Access token
     */
    IAccessToken refreshAccessToken(long issuedAt, String target, String cellUrl,
            List<Role> roleList, String schema);

    /**
     * Refresh to new Refresh Token with old refresh token.
     * @param issuedAt Issued time stamp
     * @return Refresh Token
     */
    IRefreshToken refreshRefreshToken(long issuedAt);

    /**
     * Expiration time in second of Refresh token.
     * @return Expiration time in second
     */
    int refreshExpiresIn();
}
