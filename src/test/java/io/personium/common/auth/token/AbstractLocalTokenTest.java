/**
 * Personium
 * Copyright 2019 Personium Project Authors
 *  - Akio Shimono
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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.personium.common.auth.token.AbstractOAuth2Token.TokenDsigException;
import io.personium.common.auth.token.AbstractOAuth2Token.TokenParseException;
import io.personium.common.auth.token.AbstractOAuth2Token.TokenRootCrtException;


public class AbstractLocalTokenTest {
    static Logger log = LoggerFactory.getLogger(AbstractLocalTokenTest.class);
    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void getIvBytes() throws TokenParseException, TokenDsigException, TokenRootCrtException {
        String issuer1 = "https://cell1.unit.example/";
        String issuer2 = "https://cell2.unit.example/";
        byte[] b1 = AbstractLocalToken.getIvBytes(issuer1);
        log.info(this.debugStrBytes(b1));
        assertEquals(16, b1.length);

        byte[] b2 = AbstractLocalToken.getIvBytes(issuer2);
        log.info(this.debugStrBytes(b2));
        assertEquals(16, b2.length);
    }
    private String debugStrBytes(byte[] bytes) {
        StringBuilder sb = new StringBuilder(2 * bytes.length);
        for(byte b: bytes) {
                sb.append(String.format("%02x ", b&0xff) );
        }
        return sb.toString();
    }
}
