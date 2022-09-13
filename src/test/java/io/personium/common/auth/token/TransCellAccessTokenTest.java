/**
 * Personium
 * Copyright 2014-2022 Personium Project Authors
 * - FUJITSU LIMITED
 * - Akio Shimono
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

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.naming.InvalidNameException;

import org.apache.commons.lang.StringUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import io.personium.common.auth.token.AbstractOAuth2Token.TokenDsigException;
import io.personium.common.auth.token.AbstractOAuth2Token.TokenParseException;
import io.personium.common.auth.token.AbstractOAuth2Token.TokenRootCrtException;

public class TransCellAccessTokenTest {
    static final String ISSUER = "https://issuer.localhost/";
    static final String SUBJECT = "https://subject.localhost/#acc";
    static final String TARGET = "https://target.localhost/";
    static final String SCHEMA = "https://schema.localhost/";
    static final String[] SCOPE = new String[] {"auth", "message-read"};
    static final List<Role> ROLE_LIST = new ArrayList<>();
    static final Set<String> SCOPE_SET = new HashSet<>();
    static {
        ROLE_LIST.add(new Role("role1", "box", "https://schema.localhost/", "https://schema.localhost/"));
        ROLE_LIST.add(new Role("role2", "box", "https://schema.localhost/", "https://subject.localhost/"));
    }

    TransCellAccessToken token;
    @Before
    public void setUp() throws Exception {
        String keyPath = ClassLoader.getSystemResource("x509/localhost.key").getPath();
        String crtPath = ClassLoader.getSystemResource("x509/localhost.crt").getPath();
        String cacPath = ClassLoader.getSystemResource("x509/personium_ca.crt").getPath();
        //URL r = c.getResource("x509/localhost.key");
        try {

            TransCellAccessToken.configureX509(keyPath, crtPath, new String[] {cacPath});
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | CertificateException | InvalidNameException
                | IOException e) {
            e.printStackTrace();
        }
        this.token = new TransCellAccessToken(new Date().getTime(),
                AbstractOAuth2Token.ACCESS_TOKEN_EXPIRES_MILLISECS,
                ISSUER,
                SUBJECT,
                TARGET,
                ROLE_LIST,
                SCHEMA, SCOPE);
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void parse_ParsedIssuerSubjectSchema_ShouldBe_SameAs_Original()
            throws TokenParseException, TokenDsigException, TokenRootCrtException {
        String tokenStr = this.token.toTokenString();
        // parse the prepared token
        TransCellAccessToken parsedToken = TransCellAccessToken.parse(tokenStr);
        // Parsed contents are the kept.
        assertEquals(ISSUER, parsedToken.getIssuer());
        assertEquals(SUBJECT, parsedToken.getSubject());
        assertEquals(SCHEMA, parsedToken.getSchema());
        assertEquals(TARGET, parsedToken.getTarget());
    }
    @Test
    public void parse_ParsedScopes_ShouldBe_SameAs_Original()
            throws TokenParseException, TokenDsigException, TokenRootCrtException {
        String tokenStr = this.token.toTokenString();
        // parse the prepared token
        TransCellAccessToken parsedToken = TransCellAccessToken.parse(tokenStr);
        // Parsed scopes are kept the same.
        assertEquals(StringUtils.join(SCOPE, " "), StringUtils.join(parsedToken.getScope(), " "));
    }

    @Test
    public void parse_ParsedRoles_ShouldBe_SameAs_Original()
            throws TokenParseException, TokenDsigException, TokenRootCrtException {
        String tokenStr = this.token.toTokenString();
        TransCellAccessToken parsedToken = TransCellAccessToken.parse(tokenStr);
        List<Role> parsedRoles = parsedToken.getRoleList();
        // Parsed roles should be kept the same.
        assertEquals(ROLE_LIST.size(), parsedRoles.size());
        StringBuilder sb1 = new StringBuilder();
        for (Role role : ROLE_LIST) {
            sb1.append(role.getBoxSchema() + ":" + role.getName());
            sb1.append(" ");
        }
        StringBuilder sb2 = new StringBuilder();
        for (Role role : parsedRoles) {
            sb2.append(role.getBoxSchema() + ":" + role.getName());
            sb2.append(" ");
        }
        assertEquals(sb1.toString(), sb2.toString());
    }
}
