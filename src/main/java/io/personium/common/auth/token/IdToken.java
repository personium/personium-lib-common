/**
 * Personium
 * Copyright 2019-2022 Personium Project Authors
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

import java.security.PrivateKey;

import org.apache.cxf.rs.security.jose.jws.JwsHeaders;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactProducer;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;

/**
 * Model class of id_token.
 */
public class IdToken {

    // Jws Headers.
    private String keyId;
    private String algorithm;
    // Jwt Claims.
    private String issuer;
    private String subject;
    private String audience;
    private long expiryTime;
    private long issuedAt;
    // Signature.
    private PrivateKey privateKey;

    /**
     * Constructor.
     * @param keyId keyId
     * @param algorithm algorithm
     * @param issuer issuer
     * @param subject subject
     * @param audience audience
     * @param expiryTime expiryTime
     * @param issuedAt issuedAt
     * @param privateKey privateKey
     */
    public IdToken(String keyId, String algorithm,
            String issuer, String subject, String audience, long expiryTime, long issuedAt,
            PrivateKey privateKey) {
        this.keyId = keyId;
        this.algorithm = algorithm;
        this.issuer = issuer;
        this.subject = subject;
        this.audience = audience;
        this.expiryTime = expiryTime;
        this.issuedAt = issuedAt;
        this.privateKey = privateKey;
    }

    /**
     * Create token string and return.
     * @return token string
     */
    public String toTokenString() {
        JwsHeaders jwsHeaders = new JwsHeaders();
        jwsHeaders.setKeyId(keyId);
        jwsHeaders.setAlgorithm(algorithm);

        JwtClaims claims = new JwtClaims();
        claims.setIssuer(issuer);
        claims.setSubject(subject);
        claims.setAudience(audience);
        claims.setExpiryTime(expiryTime);
        claims.setIssuedAt(issuedAt);

        JwsJwtCompactProducer producer = new JwsJwtCompactProducer(jwsHeaders, claims);
        String idTokenString = producer.signWith(privateKey);
        return idTokenString;
    }
}
