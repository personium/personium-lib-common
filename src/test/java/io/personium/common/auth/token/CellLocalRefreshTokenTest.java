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

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

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
@PrepareForTest({CellLocalRefreshToken.class})
@PowerMockIgnore({ "javax.xml.crypto.dsig.*", "javax.security.auth.*" })
public class CellLocalRefreshTokenTest {

    /** Target class of unit test. */
    private CellLocalRefreshToken cellLocalRefreshToken;

    /**
     * Before.
     */
    @Before
    public void before() {
        cellLocalRefreshToken = PowerMockito.spy(new CellLocalRefreshToken(null, null, null, null));
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
        Role role = new Role("roleName");
        roleList.add(role);

        // --------------------
        // Mock settings
        // --------------------
        IAccessToken ret = new AccountAccessToken(1L, null, null, null, null);
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
        cellLocalRefreshToken = PowerMockito.spy(new CellLocalRefreshToken(
                "https://personium/issuer/", "https://personium/subject/", "https://personium/schema/", "scope"));
        // --------------------
        // Test method args
        // --------------------
        long issuedAt = 1L;
        String target = null;
        String cellUrl = "https://personium/testcell02/";
        List<Role> roleList = new ArrayList<>();
        Role role = new Role("roleName");
        roleList.add(role);
        String schema = null;

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
        assertThat(actual, instanceOf(AccountAccessToken.class));
        AccountAccessToken castActual = (AccountAccessToken) actual;
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
        cellLocalRefreshToken = PowerMockito.spy(new CellLocalRefreshToken(
                "https://personium/issuer/", "https://personium/subject/", schema, "scope"));

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
        Role role = new Role("roleName");
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
