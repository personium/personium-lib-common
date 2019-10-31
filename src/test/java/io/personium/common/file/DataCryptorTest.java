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
package io.personium.common.file;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.InputStream;
import java.lang.reflect.Field;

import javax.crypto.Cipher;

import org.apache.commons.lang.CharEncoding;
import org.junit.BeforeClass;
import org.junit.Test;

import io.personium.common.file.CipherInputStream;
import io.personium.common.file.DataCryptor;

/**
 * Unit Test class for DataCryptor.<br>
 * Since Exception does not occur basically, it is excluded from the test.
 */
public class DataCryptorTest {

    /**
     * Befor Class.
     */
    @BeforeClass
    public static void beforClass() {
        DataCryptor.setKeyString("abcdef0123456789");
    }

    /**
     * Test constructor. Also test getIvBytes().
     * normal.
     * @throws Exception Unexpected error.
     */
    @Test
    public void dataCryptor_Normal() throws Exception {
        // --------------------
        // Test method args
        // --------------------
        String cellId = "zyxwvutsrqponmlkjih";

        // --------------------
        // Mock settings
        // --------------------
        // Nothing.

        // --------------------
        // Expected result
        // --------------------
        // Nothing.

        // --------------------
        // Run method
        // --------------------
        DataCryptor cryptor = new DataCryptor(cellId);

        // --------------------
        // Confirm result
        // --------------------
        byte[] expected = "hijklmnopqrstuvw".getBytes(CharEncoding.UTF_8);
        Field field = DataCryptor.class.getDeclaredField("iv");
        field.setAccessible(true);
        byte[] iv = (byte[]) field.get(cryptor);
        assertThat(iv, is(expected));
    }

    /**
     * Test encode().
     * normal.
     * @throws Exception Unexpected error.
     */
    @Test
    public void encode_Normal() throws Exception {
        // --------------------
        // Test method args
        // --------------------
        String str = "0123456789";
        InputStream input = new ByteArrayInputStream(str.getBytes(CharEncoding.UTF_8));

        // --------------------
        // Mock settings
        // --------------------
        // Nothing.

        // --------------------
        // Expected result
        // --------------------
        // Nothing.

        // --------------------
        // Run method
        // --------------------
        DataCryptor cryptor = new DataCryptor("zyxwvutsrqponmlk");
        CipherInputStream encodedInputStream = null;
        encodedInputStream = (CipherInputStream) cryptor.encode(input, true);

        // --------------------
        // Confirm result
        // --------------------
        Field field = FilterInputStream.class.getDeclaredField("in");
        field.setAccessible(true);
        InputStream actualInput = (InputStream) field.get(encodedInputStream);

        assertThat(actualInput, is(input));

        field = CipherInputStream.class.getDeclaredField("cipher");
        field.setAccessible(true);
        Cipher actualCipher = (Cipher) field.get(encodedInputStream);
        byte[] expectedIV = "klmnopqrstuvwxyz".getBytes(CharEncoding.UTF_8);
        String expectedAlgorithm = "AES/CBC/PKCS5Padding";

        assertThat(actualCipher.getIV(), is(expectedIV));
        assertThat(actualCipher.getAlgorithm(), is(expectedAlgorithm));
    }

    /**
     * Test decode().
     * normal.
     * @throws Exception Unexpected error.
     */
    @Test
    public void decode_Normal() throws Exception {
        // --------------------
        // Test method args
        // --------------------
        String str = "0123456789";
        InputStream input = new ByteArrayInputStream(str.getBytes(CharEncoding.UTF_8));

        // --------------------
        // Mock settings
        // --------------------
        // Nothing.

        // --------------------
        // Expected result
        // --------------------
        // Nothing.

        // --------------------
        // Run method
        // --------------------
        DataCryptor cryptor = new DataCryptor("zyxwvutsrqponmlk");
        CipherInputStream encodedInputStream = null;
        encodedInputStream = (CipherInputStream) cryptor.decode(input, DataCryptor.ENCRYPTION_TYPE_AES);

        // --------------------
        // Confirm result
        // --------------------
        Field field = FilterInputStream.class.getDeclaredField("in");
        field.setAccessible(true);
        InputStream actualInput = (InputStream) field.get(encodedInputStream);

        assertThat(actualInput, is(input));

        field = CipherInputStream.class.getDeclaredField("cipher");
        field.setAccessible(true);
        Cipher actualCipher = (Cipher) field.get(encodedInputStream);
        byte[] expectedIV = "klmnopqrstuvwxyz".getBytes(CharEncoding.UTF_8);
        String expectedAlgorithm = "AES/CBC/PKCS5Padding";

        assertThat(actualCipher.getIV(), is(expectedIV));
        assertThat(actualCipher.getAlgorithm(), is(expectedAlgorithm));
    }
}
