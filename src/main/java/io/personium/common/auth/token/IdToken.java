package io.personium.common.auth.token;

import java.security.PrivateKey;

import org.apache.cxf.rs.security.jose.jws.JwsHeaders;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactProducer;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;

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
