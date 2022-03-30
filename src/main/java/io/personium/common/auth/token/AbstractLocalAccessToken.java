/**
 * Personium
 * Copyright 2019-2022 Personium Project Authors
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

/**
 * abstract base class for classes to handle Cell Local Access Tokens.
 */
public abstract class AbstractLocalAccessToken extends AbstractLocalToken implements IAccessToken {
    /**
     * Default Constructor.
     */
    protected AbstractLocalAccessToken() {
    }

    /**
     * Constructor.
     * @param issuedAt Token issuance datetime (millisec from the epoch)
     * @param lifespan Token lifespan (in millisec)
     * @param issuer Token issuer
     * @param subject Token Subject
     * @param schema Token Schema
     * @param scope Token scope
     */
    public AbstractLocalAccessToken(final long issuedAt, final long lifespan, final String issuer,
             final String subject, final String schema, String[] scope) {
        this.issuedAt = issuedAt;
        this.lifespan = lifespan;
        this.issuer = issuer;
        this.subject = subject;
        this.schema = schema;
        this.scope = scope;
    }

    public String getCookieString(String peer, String issuer) {
        String raw = peer + SEPARATOR + this.toTokenString();
        return AbstractLocalAccessToken.encode(raw, AbstractLocalAccessToken.getIvBytes(issuer));
    }
}
