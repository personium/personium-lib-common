/**
 * Personium
 * Copyright 2014 Personium Project Authors
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.net.MalformedURLException;
import java.net.URL;

import org.junit.Test;

/**
 * Unit test class for Role class.
 */
public class RoleTest {

    /**
     * test for the constructor.
     * @throws MalformedURLException
     */
    @Test
    public void testRoleConstruct() throws MalformedURLException {
        String baseUrl = "https://localhost:8080/personium-core/testcell1/";
        String roleUrl = "__role/__/role1";
        URL url = new URL(baseUrl + roleUrl);
        Role role = new Role(url);
        assertNotNull(role);
        assertEquals(baseUrl, role.getBaseUrl());
    }

    /**
     * test for the constructor.
     * (URL is configured only upto baseURL).
     * @throws MalformedURLException
     */
    @Test(expected = MalformedURLException.class)
    public void testRoleConstructWithBaseUrl() throws MalformedURLException {
        String baseUrl = "https://localhost:8080/personium-core/testcell1/";
        String roleUrl = "";
        URL url = new URL(baseUrl + roleUrl);
        new Role(url);
    }

    /**
     * test for the constructor (URL is cut after "__role").
     * @throws MalformedURLException
     */
    @Test(expected = MalformedURLException.class)
    public void testRoleConstructWithUnderbar() throws MalformedURLException {
        String baseUrl = "https://localhost:8080/personium-core/testcell1/";
        String roleUrl = "__role";
        URL url = new URL(baseUrl + roleUrl);
        new Role(url);
    }

    /**
     * test for the constructor (URL is cut after the box name).
     * @throws MalformedURLException
     */
    @Test(expected = MalformedURLException.class)
    public void testRoleConstructWithBox() throws MalformedURLException {
        String baseUrl = "https://localhost:8080/personium-core/testcell1/";
        String roleUrl = "__role/__";
        URL url = new URL(baseUrl + roleUrl);
        new Role(url);
    }

    /**
     * Roleのコンストラクタのテスト(URLがURL形式ではない).
     * @throws MalformedURLException
     */
    @Test(expected = MalformedURLException.class)
    public void testRoleConstructWithBadURL() throws MalformedURLException {
        String baseUrl = "BadURL";
        URL url = new URL(baseUrl);
        new Role(url);
    }

}
