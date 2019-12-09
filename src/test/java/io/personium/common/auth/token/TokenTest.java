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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.MalformedURLException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.BeforeClass;
import org.junit.Test;

import io.personium.common.auth.token.AbstractOAuth2Token.TokenDsigException;
import io.personium.common.auth.token.AbstractOAuth2Token.TokenParseException;
import io.personium.common.auth.token.AbstractOAuth2Token.TokenRootCrtException;

/**
 * Unit test class for token processing libraries.
 */
public class TokenTest {
    /**
     * Initial configuration for token processing libraries.
     * @throws IOException IOException
     * @throws CertificateException CertificateException
     * @throws InvalidKeySpecException InvalidKeySpecException
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws javax.security.cert.CertificateException CertificateException
     * @throws javax.naming.InvalidNameException InvalidNameException
     */
    @BeforeClass
    public static void beforeClass()
            throws NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, IOException,
            javax.security.cert.CertificateException, javax.naming.InvalidNameException {
        TransCellAccessToken.configureX509(null, null, null);
        AbstractLocalToken.setKeyString("abcdef0123456789");
    }

    /**
     * test ResidentLocalAccessToken.
     * @throws MalformedURLException
     */
    @Test
    public void testResidentLocalAccessToken() {
        String issuer = "http://issuer.example/";
        ResidentLocalAccessToken token = new ResidentLocalAccessToken(new Date().getTime(), issuer,
                "http://orig.com/orig/#subj", "http://schema.com/schema", new String[] {"someScope"});
        String tokenStr = token.toTokenString();

        ResidentLocalAccessToken token2 = null;
        try {
            token2 = ResidentLocalAccessToken.parse(tokenStr, issuer);
            assertEquals(tokenStr, token2.toTokenString());
        } catch (AbstractOAuth2Token.TokenParseException e) {
            fail(e.getMessage());
        }
    }


    /**
     * test ResidentRefreshToken.
     * @throws MalformedURLException
     */
    @Test
    public void testResidentRefreshToken() throws MalformedURLException {
        String issuer = "http://receiver.com/rcv";

        ResidentRefreshToken token = new ResidentRefreshToken(new Date().getTime(), issuer,
                "http://orig.com/orig/#subj",  "http://schema.com/schema", new String[] {"someScope"});
        String tokenStr = token.toTokenString();

        ResidentRefreshToken token2 = null;
        try {
            token2 = ResidentRefreshToken.parse(tokenStr, issuer);
            assertEquals(tokenStr, token2.toTokenString());
        } catch (AbstractOAuth2Token.TokenParseException e) {
            fail(e.getMessage());
        }
    }
    /**
     * test VisitorRefreshToken.
     * @throws MalformedURLException
     */
    @Test
    public void testVisitorRefreshToken() throws MalformedURLException {
        String base = "https://localhost:8080/personium-core/testcell1/__role/__/";
        List<Role> roleList = new ArrayList<Role>();
        roleList.add(Role.createFromRoleClassUrl(base + "admin"));
        roleList.add(Role.createFromRoleClassUrl(base + "staff"));
        roleList.add(Role.createFromRoleClassUrl(base + "doctor"));

        String id = "1234";
        VisitorRefreshToken token = new VisitorRefreshToken(id, new Date().getTime(),
                AbstractOAuth2Token.REFRESH_TOKEN_EXPIRES_MILLISECS,
                "http://receiver.com/rcv",
                "http://orig.com/orig/#subj",
                "http://orig.com/orig",
                roleList,
                "http://schema.com/schema",
                null);
        String tokenStr = token.toTokenString();

        VisitorRefreshToken token2 = null;
        try {
            token2 = VisitorRefreshToken.parse(tokenStr, "http://receiver.com/rcv");
            assertEquals(tokenStr, token2.toTokenString());
        } catch (AbstractOAuth2Token.TokenParseException e) {
            fail(e.getMessage());
        }
    }


    /**
     * test TransCellAccessToken.
     * @throws TokenParseException TokenParseException
     * @throws TokenRootCrtException TokenRootCrtException
     * @throws TokenDsigException TokenDsigException
     * @throws MalformedURLException
     */
    @Test
    public void testTransCellAccessToken() throws TokenParseException, TokenDsigException, TokenRootCrtException, MalformedURLException {
        String cellRootUrl = "https://localhost/TranscellAccessTokenTestCell/";
        String target = "https://example.com/targetCell/";
        String schema = "https://example.com/schemaCell/";

        String base = cellRootUrl + "__role/__/";
        List<Role> roleList = new ArrayList<Role>();
        roleList.add(Role.createFromRoleClassUrl(base + "admin"));
        roleList.add(Role.createFromRoleClassUrl(base + "staff"));
        roleList.add(Role.createFromRoleClassUrl(base + "doctor"));

        TransCellAccessToken tcToken = new TransCellAccessToken(
                cellRootUrl, cellRootUrl + "#admin", target, roleList,
                schema, new String[] {"someScope"});

        String token = tcToken.toTokenString();

        TransCellAccessToken tcToken2 = TransCellAccessToken.parse(token);
        assertEquals(target, tcToken2.getTarget());

        for (Role role : roleList) {
            boolean hit = false;
            for (Role role2 : tcToken2.getRoleList()) {
                String roleUrl = role.toRoleClassURL();
                if (roleUrl.equals(role2.toRoleClassURL())) {
                    hit = true;
                }
            }
            assertTrue(hit);
        }
    }
    /**
     * test VisitorLocalAccessToken.
     * @throws MalformedURLException
     * @throws TokenParseException
     */
    @Test
    public void testVisitorLocalAccessToken() throws MalformedURLException, TokenParseException {
        String base = "https://localhost:8080/personium-core/testcell1/__role/__/";
        List<Role> roleList = new ArrayList<Role>();
        roleList.add(Role.createFromRoleClassUrl(base + "admin"));
        roleList.add(Role.createFromRoleClassUrl(base + "staff"));
        roleList.add(Role.createFromRoleClassUrl(base + "doctor"));

        VisitorLocalAccessToken token = new VisitorLocalAccessToken(
                new Date().getTime(),
                VisitorLocalAccessToken.ACCESS_TOKEN_EXPIRES_MILLISECS,
                "http://hogte.com/", "http://hige.com", roleList,
                "http://example.com/schema", new String[] {"someScope"});

        String tokenStr = token.toTokenString();

        VisitorLocalAccessToken token2 = null;
            token2 = VisitorLocalAccessToken.parse(tokenStr, "http://hogte.com/");
            assertEquals(tokenStr, token2.toTokenString());
    }
}
