/**
 * Personium
 * Copyright 2019-2022 Personium Project Authors
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

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

/**
 * Unit Test class for CellLocalRefreshToken.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ResidentRefreshToken.class})
@PowerMockIgnore({ "javax.xml.crypto.dsig.*", "javax.security.auth.*" })
public class ResidentRefreshTokenTest {

    /** Target class of unit test. */
    private ResidentRefreshToken cellLocalRefreshToken;

    /**
     * Before.
     */
    @Before
    public void before() {
        cellLocalRefreshToken = PowerMockito.spy(new ResidentRefreshToken(null, null, null, null));
    }

    /**
     * Test refreshAccessToken().
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    @Test
    public void refreshAccessToken_Normal() {
        // --------------------
        // Test method args
        // --------------------
        long issuedAt = 1L;
        String target = "https://personium/targetcell/";
        String cellUrl = "https://personium/testcell/";
        List<Role> roleList = new ArrayList<>();
        Role role = new Role("roleName", null, null, cellUrl);
        roleList.add(role);

        // --------------------
        // Mock settings
        // --------------------
        IAccessToken ret = new ResidentLocalAccessToken(1L, null, null, null, null);
        ArgumentCaptor<Long> issuedAtCaptor = ArgumentCaptor.forClass(Long.class);
        ArgumentCaptor<String> targetCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> cellUrlCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<List> roleListCaptor = ArgumentCaptor.forClass(List.class);
        PowerMockito.doReturn(ret).when(cellLocalRefreshToken).refreshAccessToken(
                issuedAtCaptor.capture(), targetCaptor.capture(), cellUrlCaptor.capture(),
                roleListCaptor.capture());

        // --------------------
        // Expected result
        // --------------------
        // Nothing.

        // --------------------
        // Run method
        // --------------------
        cellLocalRefreshToken.refreshAccessToken(issuedAt, target, cellUrl, roleList);

        // --------------------
        // Confirm result
        // --------------------
        assertThat(issuedAtCaptor.getValue(), is(issuedAt));
        assertThat(targetCaptor.getValue(), is(target));
        assertThat(cellUrlCaptor.getValue(), is(cellUrl));
        assertThat(roleListCaptor.getValue(), is(roleList));
    }

    /**
     * Test refreshAccessToken().
     * schema is null.
     * target is null.
     */
    @Test
    public void refreshAccessToken_Normal_schema_is_null_target_is_null() {
        cellLocalRefreshToken = PowerMockito.spy(new ResidentRefreshToken(
                "https://personium/issuer/", "https://personium/subject/", "https://personium/schema/",
                new String[] {"scope"}));
        // --------------------
        // Test method args
        // --------------------
        long issuedAt = 1L;
        String target = null;
        String cellUrl = "https://personium/testcell02/";
        List<Role> roleList = new ArrayList<>();
        Role role = new Role("roleName", null, null, cellUrl);
        roleList.add(role);

        // --------------------
        // Mock settings
        // --------------------
        // Nothing.

        // --------------------
        // Expected result
        // --------------------
        Long expectedIssuedAt = issuedAt;
        String expectedIssuer = "https://personium/issuer/";
        String expectedSubject = "https://personium/subject/";
        String expectedSchema = "https://personium/schema/";

        // --------------------
        // Run method
        // --------------------
        IAccessToken actual = cellLocalRefreshToken.refreshAccessToken(issuedAt, target, cellUrl, roleList);

        // --------------------
        // Confirm result
        // --------------------
        assertThat(actual, instanceOf(ResidentLocalAccessToken.class));
        ResidentLocalAccessToken castActual = (ResidentLocalAccessToken) actual;
        assertThat(castActual.issuedAt, is(expectedIssuedAt));
        assertThat(castActual.getIssuer(), is(expectedIssuer));
        assertThat(castActual.getSubject(), is(expectedSubject));
        assertThat(castActual.getSchema(), is(expectedSchema));
    }

    /**
     * Test refreshAccessToken().
     * schema is not null.
     * target is not null.
     * @throws Exception Unexpected error.
     */
    @Test
    public void refreshAccessToken_Normal_schema_not_null_target_not_null() throws Exception {
        String schema = "https://personium/schema/";
        cellLocalRefreshToken = PowerMockito.spy(new ResidentRefreshToken(
                "https://personium/issuer/", "https://personium/subject/", schema, new String[] {"scope"}));

        // X509 settings.
        String folderPath = "x509/effective/";
        String privateKeyFileName = ClassLoader.getSystemResource(folderPath + "pio.key").getPath();
        String certificateFileName = ClassLoader.getSystemResource(folderPath + "pio.crt").getPath();
        String[] rootCertificateFileNames = new String[1];
        rootCertificateFileNames[0] = ClassLoader.getSystemResource(folderPath + "cacert.crt").getPath();
        TransCellAccessToken.configureX509(privateKeyFileName, certificateFileName, rootCertificateFileNames);

        // --------------------
        // Test method args
        // --------------------
        long issuedAt = 1L;
        String target = "https://personium/targetcell/";
        String cellUrl = "https://personium/testcell02/";
        List<Role> roleList = new ArrayList<>();
        Role role = new Role("roleName", null, null, cellUrl);
        roleList.add(role);

        // --------------------
        // Mock settings
        // --------------------
        // Nothing.

        // --------------------
        // Expected result
        // --------------------
        Long expectedIssuedAt = issuedAt;
        String expectedIssuer = "https://personium/issuer/";
        String expectedSubject = cellUrl + "#" + "https://personium/subject/";
        String expectedTarget = target;
        List<Role> expectedRoleList = roleList;
        String expectedSchema = schema;

        // --------------------
        // Run method
        // --------------------
        IAccessToken actual = cellLocalRefreshToken.refreshAccessToken(issuedAt, target, cellUrl, roleList);

        // --------------------
        // Confirm result
        // --------------------
        assertThat(actual, instanceOf(TransCellAccessToken.class));
        TransCellAccessToken castActual = (TransCellAccessToken) actual;
        assertThat(castActual.issuedAt, is(expectedIssuedAt));
        assertThat(castActual.getIssuer(), is(expectedIssuer));
        assertThat(castActual.getSubject(), is(expectedSubject));
        assertThat(castActual.getTarget(), is(expectedTarget));
        assertThat(castActual.getRoleList(), is(expectedRoleList));
        assertThat(castActual.getSchema(), is(expectedSchema));
    }
}
