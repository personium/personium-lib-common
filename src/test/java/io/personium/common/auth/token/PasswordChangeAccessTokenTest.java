/**
 * Personium
 * Copyright 2014-2019 Personium Project Authors
 *  - FUJITSU LIMITED
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Date;

import javax.crypto.SecretKey;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import io.personium.common.auth.token.AbstractOAuth2Token.TokenParseException;

/**
 * Unit Test class for PasswordChangeAccessToken.
 */
public class PasswordChangeAccessTokenTest {
    static final Long ISSUED_AT = new Date().getTime();
    static final Long LIFESPAN = AbstractOAuth2Token.ACCESS_TOKEN_EXPIRES_MILLISECS;
    static final String ISSUER = "https://issuer.localhost/";
    static final String SUBJECT = "https://subject.localhost/#acc";
    static String TARGET = "https://target.localhost/";
    static String SCHEMA = "https://schema.localhost/";
    static String[] SCOPE = new String[] {"auth", "message-read"};

    static byte[] shelterKeyBytes;
    static SecretKey shelterAesKey;

    @BeforeClass
    public static void beforeClass() {
        shelterKeyBytes = AbstractLocalToken.keyBytes;
        shelterAesKey = AbstractLocalToken.aesKey;
        AbstractLocalToken.setKeyString("0123456789abcdef");
    }
    @AfterClass
    public static void afterClass() {
        AbstractLocalToken.keyBytes = shelterKeyBytes;
        AbstractLocalToken.aesKey = shelterAesKey;
    }


    @Test
    public void parse() throws TokenParseException {
        PasswordChangeAccessToken token = new PasswordChangeAccessToken(
                ISSUED_AT, LIFESPAN,
                ISSUER, SUBJECT, SCHEMA, SCOPE
            );
        String tokenStr = token.toTokenString();
        // --------------------
        // Run method
        // --------------------
        PasswordChangeAccessToken t = PasswordChangeAccessToken.parse(tokenStr, ISSUER);

        // --------------------
        // Confirm result
        // --------------------
        assertEquals(ISSUED_AT, Long.valueOf(t.issuedAt));
        assertEquals(LIFESPAN, Long.valueOf(t.lifespan));
        assertEquals(ISSUER, t.getIssuer());
        assertEquals(SCHEMA, t.getSchema());
        assertEquals(SUBJECT, t.getSubject());
        assertTrue(Arrays.deepEquals(SCOPE, t.getScope()));
    }
}
