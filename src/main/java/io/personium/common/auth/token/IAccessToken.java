/**
 * Personium
 * Copyright 2019-2022 Personium Project Authors
 * - FUJITSU LIMITED
 * - (Add authors here)
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
 * OAuth2.0 Access Token Interface used in Personium.
 */
public interface IAccessToken {
    /**
     * returns the token's identifier.
     * @return the token's identifier
     */
    String getId();
    /**
     * returns token subject.
     * @return token subject
     */
    String getSubject();
    /**
     * returns access token target.
     * @return access token target
     */
    String getTarget();

    /**
     * returns access token SCHEMA (client id).
     * @return SCHEMA URL (client id)
     */
    String getSchema();

    /**
     * returns the scopes of access token.
     * @return array of scope strings
     */
    String[] getScope();

    /**
     * constructs token string.
     * @return token string
     */
    String toTokenString();

    /**
     * constructs p_cookie string.
     * @param cookiePeer Cookie Peer string
     * @param issuer issuer
     * @return cookie string
     */
    String getCookieString(String cookiePeer, String issuer);

    /**
     * returns the time in seconds till the token expiration.
     * @return time in seconds till the token expiration
     */
    int expiresIn();
}
