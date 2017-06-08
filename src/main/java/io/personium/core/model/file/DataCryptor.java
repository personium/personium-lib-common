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
package io.personium.core.model.file;

import java.io.InputStream;
import java.io.UnsupportedEncodingException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.CharEncoding;
import org.apache.commons.lang.StringUtils;

/**
 * Class for encrypting / decrypting data.
 */
public class DataCryptor {

    /** EncryptionType:none. */
    public static final String ENCRYPTION_TYPE_NONE = "NONE";
    /** EncryptionType:AES. */
    public static final String ENCRYPTION_TYPE_AES = "AES";

    /** AES/CBC/PKCS5Padding. */
    private static final String AES_CBC_PKCS5_PADDING = "AES/CBC/PKCS5Padding";
    /** IV length. */
    private static final int IV_BYTE_LENGTH = 16;

    /** AES secret key. */
    private static SecretKey aesKey;

    /** AES IV. */
    private byte[] iv;

    /**
     * Set secret key.
     * @param keyString key string
     */
    public static void setKeyString(String keyString) {
        aesKey = new SecretKeySpec(keyString.getBytes(), "AES");
    }

    /**
     * constructor.<br>
     * Generate IV(Initial Vector) from cell ID.
     * @param cellId Cell ID
     */
    public DataCryptor(String cellId) {
        iv = createIvBytes(cellId);
    }

    /**
     * Generate IV(Initial Vector) from cell ID.<br>
     * Use the character string with the last 16 characters reversed.
     * @param cellId Cell ID
     * @return Generated IV
     */
    private byte[] createIvBytes(String cellId) {
        try {
            // Add 16 characters to the beginning assuming the case of less than 16 characters.
            return StringUtils.reverse("123456789abcdefg" + cellId)
                    .substring(0, IV_BYTE_LENGTH).getBytes(CharEncoding.UTF_8);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Generate InputStream for encryption from Input and return it.
     * @param input input data
     * @return InputStream for encryption
     */
    public InputStream encode(InputStream input) {
        try {
            Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
            CipherInputStream encodedInputStream = new CipherInputStream(input, cipher);

            return encodedInputStream;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Generate InputStream for decryption from Input and return it.
     * @param input input data
     * @return InputStream for decryption
     */
    public InputStream decode(InputStream input) {
        try {
            Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
            CipherInputStream decodedInputStream = new CipherInputStream(input, cipher);

            return decodedInputStream;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
