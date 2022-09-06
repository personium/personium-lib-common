/**
 * Personium
 * Copyright 2014-2022 Personium Project Authors
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

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Unit Test class for VisitorRefreshTokenTest.
 */
public class VisitorRefreshTokenTest {
    static Logger log = LoggerFactory.getLogger(VisitorRefreshTokenTest.class);

    static final Long ISSUED_AT = new Date().getTime();
    static final Long LIFESPAN = AbstractOAuth2Token.ACCESS_TOKEN_EXPIRES_MILLISECS;

    static final String ISSUER = "https://issuer.localhost/";
    static final String SUBJECT = "https://subject.localhost/#acc";
    static String TARGET = "https://target.localhost/";
    static String SCHEMA = "https://schema.localhost/";
    static String[] SCOPE = new String[] {"auth", "message-read"};
    static List<Role> ROLE_LIST = new ArrayList<>();
    static Set<String> SCOPE_SET = new HashSet<>();
    static {
        ROLE_LIST.add(new Role("role1", "box", "https://schema.localhost/", "https://schema.localhost/"));
        ROLE_LIST.add(new Role("role2", "box", "https://schema.localhost/", "https://subject.localhost/"));
    }


    /** Target class of unit test. */
    private VisitorRefreshToken visitorRefreshToken;

    @BeforeClass
    public static void beforeClass() {
        AbstractLocalToken.setKeyString("a123456789abcdef");
    }

    /**
     * Before.
     */
    @Before
    public void before() {
        visitorRefreshToken = new VisitorRefreshToken(
                "12345",
                ISSUED_AT,
                LIFESPAN,
                ISSUER,
                SUBJECT,
                ISSUER,
                ROLE_LIST,
                SCHEMA,
                SCOPE);
    }

    /**
     * Test refreshAccessToken().
     */
    @Test
    public void refreshAccessToken_Normal() {
        // --------------------
        // Test method args
        // --------------------
//        long issuedAt = 1L;
//        String target = "https://personium/targetcell/";
//        String cellUrl = "https://personium/testcell/";
//        List<Role> roleList = new ArrayList<>();
//        Role role = new Role("roleName");
//        roleList.add(role);

        // --------------------
        // Mock settings
        // --------------------

//        IAccessToken ret = new ResidentLocalAccessToken(1L, null, null, null, null);
//        ArgumentCaptor<Long> issuedAtCaptor = ArgumentCaptor.forClass(Long.class);
//        ArgumentCaptor<String> targetCaptor = ArgumentCaptor.forClass(String.class);
//        ArgumentCaptor<String> cellUrlCaptor = ArgumentCaptor.forClass(String.class);
//        ArgumentCaptor<List> roleListCaptor = ArgumentCaptor.forClass(List.class);
//        Mockito.doReturn(ret).when(visitorRefreshToken).refreshAccessToken(
//                issuedAtCaptor.capture(), targetCaptor.capture(), cellUrlCaptor.capture(),
//                roleListCaptor.capture());

        // --------------------
        // Expected result
        // --------------------
        // Nothing.
        Long refreshedAt = ISSUED_AT + LIFESPAN * 2;

        // --------------------
        // Run method
        // --------------------
        VisitorLocalAccessToken at = (VisitorLocalAccessToken) visitorRefreshToken
                .refreshAccessToken(refreshedAt, LIFESPAN, null, ISSUER, ROLE_LIST);

        // --------------------
        // Confirm result
        // --------------------
        assertEquals(refreshedAt, Long.valueOf(at.issuedAt));
        assertEquals(ISSUER, at.getIssuer());
        assertEquals(SUBJECT, at.getSubject());
        assertEquals(SCHEMA, at.getSchema());
        assertTrue(Arrays.deepEquals(ROLE_LIST.toArray(), at.getRoleList().toArray()));
    }

    /**
     * Test refreshAccessToken().
     * schema is null.
     * target is null.
     */
    @Test
    public void refreshAccessToken_Normal_schema_is_null_target_is_null() {
        // --------------------
        // Test method args
        // --------------------


        Long refreshedAt = ISSUED_AT + LIFESPAN * 2;

        // --------------------
        // Run method
        // --------------------
        IAccessToken actual = visitorRefreshToken.refreshAccessToken(refreshedAt, LIFESPAN, null, ISSUER, ROLE_LIST);

        // --------------------
        // Confirm result
        // --------------------
        assertThat(actual, instanceOf(VisitorLocalAccessToken.class));
        VisitorLocalAccessToken castActual = (VisitorLocalAccessToken) actual;
        assertEquals(refreshedAt, Long.valueOf(castActual.issuedAt));
        assertEquals(ISSUER, castActual.getIssuer());
        assertEquals(SUBJECT, castActual.getSubject());
        assertEquals(SCHEMA, castActual.getSchema());
        assertTrue(Arrays.deepEquals(ROLE_LIST.toArray(), castActual.getRoleList().toArray()));
    }

    /**
     * Test refreshAccessToken().
     * schema is not null.
     * target is not null.
     * @throws Exception Unexpected error.
     */
    @Test
    public void refreshAccessToken_Normal_schema_not_null_target_not_null() throws Exception {
        // --------------------
        // Test method args
        // --------------------
//        long issuedAt = 1L;
//        String subject = "https://personium/subject/";
//        String target = "https://personium/targetcell/";
//        String cellUrl = "https://personium/testcell02/";
//        List<Role> roleList = new ArrayList<>();
//        Role role = new Role("roleName");
//        roleList.add(role);
//        String schema = "https://personium/appcell/";

//        visitorRefreshToken = new VisitorRefreshToken(
//                null, null, subject, null, null, schema, null);

        // X509 settings.
        String folderPath = "x509/effective/";
        String privateKeyFileName = ClassLoader.getSystemResource(folderPath + "pio.key").getPath();
        String certificateFileName = ClassLoader.getSystemResource(folderPath + "pio.crt").getPath();
        String[] rootCertificateFileNames = new String[1];
        rootCertificateFileNames[0] = ClassLoader.getSystemResource(folderPath + "cacert.crt").getPath();
        TransCellAccessToken.configureX509(privateKeyFileName, certificateFileName, rootCertificateFileNames);


        // --------------------
        // Mock settings
        // --------------------
        // Nothing.

        // --------------------
        // Expected result
        // --------------------
        Long refreshedAt = ISSUED_AT + LIFESPAN * 2;

        // --------------------
        // Run method
        // --------------------
        IAccessToken actual = visitorRefreshToken.refreshAccessToken(refreshedAt, LIFESPAN, TARGET, ISSUER, ROLE_LIST);

        // --------------------
        // Confirm result
        // --------------------
        assertThat(actual, instanceOf(TransCellAccessToken.class));
        TransCellAccessToken castActual = (TransCellAccessToken) actual;
        assertThat(castActual.issuedAt, is(refreshedAt));
        assertThat(castActual.getIssuer(), is(ISSUER));
        assertThat(castActual.getSubject(), is(SUBJECT));
        assertThat(castActual.getTarget(), is(TARGET));
        assertThat(castActual.getRoleList(), is(ROLE_LIST));
        assertThat(castActual.getSchema(), is(SCHEMA));
    }
    @Test
    public void parse_ParsedRoles_ShouldBe_SameAs_Original() throws Exception {
        VisitorRefreshToken vrt = new VisitorRefreshToken(
                "12345",
                new Date().getTime(),
                AbstractOAuth2Token.ACCESS_TOKEN_EXPIRES_MILLISECS,
                ISSUER,
                SUBJECT,
                ISSUER,
                ROLE_LIST,
                SCHEMA,
                SCOPE);
        String tokenStr = vrt.toTokenString();
        VisitorRefreshToken parsedToken = VisitorRefreshToken.parse(tokenStr, ISSUER);
        List<Role> parsedRoles = parsedToken.getRoleList();
        // Parsed roles should be kept the same.
        assertEquals(ROLE_LIST.size(), parsedRoles.size());
        StringBuilder sb1 = new StringBuilder();
        for (Role role : ROLE_LIST) {
            sb1.append(role.toRoleClassURL());
            sb1.append(" ");
        }
        StringBuilder sb2 = new StringBuilder();
        for (Role role : parsedRoles) {
            sb2.append(role.toRoleClassURL());
            sb2.append(" ");
        }
        log.info(sb1.toString());
        log.info(sb2.toString());
        assertEquals(sb1.toString(), sb2.toString());
    }
}
