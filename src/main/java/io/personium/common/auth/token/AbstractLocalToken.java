/**
 * Personium
 * Copyright 2019 Personium Project Authors
 * - Akio Shimono
 * - FUJITSU LIMITED
 * - (Add Authors here)
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

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.CharEncoding;
import org.apache.commons.lang.StringUtils;

import io.personium.common.utils.CommonUtils;

/**
 * abstract base class for classes to handle Cell Local Tokens.
 */
public abstract class AbstractLocalToken extends AbstractOAuth2Token {

    /**
     * AES/CBC/PKCS5Padding.
     */
    public static final String AES_CBC_PKCS5_PADDING = "AES/CBC/PKCS5Padding";
    static final String SEPARATOR = "\t";
    static final String MD5 = "MD5";
    static final String AES = "AES";
    static final int IV_BYTE_LENGTH = 16;

    static byte[] keyBytes;
    static SecretKey aesKey;

    public static class Type {
        public static class AccessToken {
            public static int SELF_LOCAL = 0;
            public static int VISITOR_LOCAL = 1;
            public static int TRANC_CELL = 2;
            public static int UNIT_LOCLAL_UNIT_USER = 6;
            public static int PASSWORDCHANGE = 7;
        }
        public static class RefreshToken {
            public static int RESIDENT = 3;
            public static int VISITOR = 4;
        }
        public static int GRANT_CODE = 5;
    }

    /**
     * set the Key string.
     * @param keyString Key String.
     */
    public static void setKeyString(String keyString) {
        keyBytes = keyString.getBytes(); // 16/24/32 byte key byte array
        aesKey = new SecretKeySpec(keyBytes, AES);
    }

    /**
     * Default Constructor.
     */
    protected AbstractLocalToken() {
    }


    /**
     * generates a token by explicitly specifying the contents.
     * @param issuedAt time when the token is issued at (millisec from the epoch)
     * @param lifespan valid time (in millisec)
     * @param issuer Issuer
     * @param subject Subject
     * @param schema Schema
     * @param scope Scope
     */
    public AbstractLocalToken(final long issuedAt, final long lifespan, final String issuer,
             final String subject, final String schema, String[] scope) {
        this.issuedAt = issuedAt;
        this.lifespan = lifespan;
        this.issuer = issuer;
        this.subject = subject;
        this.schema = schema;
        this.scope = scope;
    }

    static final int IDX_ISSUED_AT = 0;
    static final int IDX_TYPE = 1;
    static final int IDX_LIFESPAN = 2;
    static final int IDX_SUBJECT = 3;
    static final int IDX_SCHEMA = 4;
    static final int IDX_SCOPE = 5;
    static final int IDX_ISSUER = 6;

    static final int COUNT_IDX = 7;


    final String doCreateTokenString(final String[] extendedFields) {
        StringBuilder raw = new StringBuilder();

        // Make it difficult to attack.
        // by starting from the reverse string of epoch millisec of issue time.
        // since starting part will change instant-by-instant.
        String iaS = Long.toString(this.issuedAt);
        String iaSr = StringUtils.reverse(iaS);
        raw.append(iaSr);
        raw.append(SEPARATOR);
        raw.append(String.valueOf(this.getType()));

        raw.append(SEPARATOR);
        raw.append(Long.toString(this.lifespan));
        raw.append(SEPARATOR);
        raw.append(this.subject);
        raw.append(SEPARATOR);
        if (this.schema != null) {
            raw.append(this.schema);
        }
        raw.append(SEPARATOR);
        if (this.scope != null) {
            raw.append(Scope.toConcatValue(this.scope));
        }
        raw.append(SEPARATOR);
        raw.append(this.issuer);

        if (extendedFields != null) {
            for (String cont : extendedFields) {
                raw.append(SEPARATOR);
                if (cont != null) {
                    raw.append(cont);
                }
            }
        }
        return encode(raw.toString(), getIvBytes(issuer));
    }


    /**
     * parse token string.
     * It also checks if the number of the fields is as expected.
     * and if the issuer of the parsed token is as expected.
     * @param token token to parsing
     * @param issuer assumed issuer
     * @param numFields expected number of fields
     * @return parsed token as an string array.
     * @throws AbstractOAuth2Token.TokenParseException when failed to parse the token
     */
    static String[] doParse(final String token, final String issuer,
      final int numFields) throws AbstractOAuth2Token.TokenParseException {
        String tokenDecoded = decode(token, getIvBytes(issuer));

        // need 2nd argument -1 to handle the case where extra frags are empty
        //
        String[] frag = tokenDecoded.split(SEPARATOR, -1);

        // If the number of the fields is not as expected
        if (frag.length != numFields) {
            throw new TokenParseException(
                "unexpected field length, expected: [" + numFields +"], actual=[" + frag.length + "]"
            );
        }

        // If the issuer mismatch, throw exception
        if (!issuer.equals(frag[IDX_ISSUER])) {
            throw new TokenParseException(
                "issuer mismatch, expected: [" + issuer +"], actual=[" + frag[IDX_ISSUER] + "]"
            );
        }

        return frag;
    }

    public String[] populate(final String token, final String issuer, int numExtraFields) throws TokenParseException {
        String[] frag = doParse(token, issuer, numExtraFields + 7);
        if (this.getType() != Integer.valueOf(frag[IDX_TYPE])) {
            throw new TokenParseException("Malformed Token : Token Type mismatch");
        }
        this.issuedAt = Long.valueOf(StringUtils.reverse(frag[IDX_ISSUED_AT]));
        this.lifespan =  Long.valueOf(frag[IDX_LIFESPAN]);
        this.subject =  frag[IDX_SUBJECT];
        this.issuer =  frag[IDX_ISSUER];
        this.schema =  frag[IDX_SCHEMA];
        this.scope =  Scope.parse(frag[IDX_SCOPE]);
        return Arrays.copyOfRange(frag, 7, frag.length);
    }

    /**
     * Generate an IV (Initial Vector) and return it for a specified token issuer.
     * @param issuer Issuer URL
     * @return Initial Vector Byte array
     */
    protected static byte[] getIvBytes(final String issuer) {
        try {
            MessageDigest md = MessageDigest.getInstance(MD5);
            byte[] hash = md.digest(issuer.getBytes(CharEncoding.UTF_8));
            return hash;
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * encode a string using an initial vector.
     * @param in plain string to encode
     * @param ivBytes Initial Vector bytes
     * @return encoded string
     */
    public static String encode(final String in, final byte[] ivBytes) {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(ivBytes));
            byte[] cipherBytes = cipher.doFinal(in.getBytes(CharEncoding.UTF_8));
            return CommonUtils.encodeBase64Url(cipherBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * decode a ciphered string using an initial vector.
     * @param in ciphered string
     * @param ivBytes Initial Vector bytes
     * @return decoded string
     * @throws AbstractOAuth2Token.TokenParseException
     */
    public static String decode(final String in, final byte[] ivBytes) throws AbstractOAuth2Token.TokenParseException {
        byte[] inBytes = CommonUtils.decodeBase64Url(in);
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(ivBytes));
            byte[] plainBytes;
            plainBytes = cipher.doFinal(inBytes);
            return new String(plainBytes, CharEncoding.UTF_8);
        } catch (Exception e) {
            throw new TokenParseException(e);
        }
    }

    abstract int getType();
    public String getId() {
        return this.subject + this.issuedAt;
    }

    public static String parseCookie(String pCookieAuthValue, String pCookiePeer, String issuer, boolean validatePeer)
            throws TokenParseException {
        if (null == pCookieAuthValue) {
            throw new TokenParseException("cookie null");
        }
        String decodedCookieValue = AbstractLocalToken.decode(pCookieAuthValue,
                        UnitLocalUnitUserToken.getIvBytes(issuer));
        int separatorIndex = decodedCookieValue.indexOf(SEPARATOR);
        String peer = decodedCookieValue.substring(0, separatorIndex);
        //Obtain authorizationHeader equivalent token from information in cookie
        String authToken = decodedCookieValue.substring(separatorIndex + 1);
        if (!validatePeer || pCookiePeer.equals(peer)) {
            //Generate appropriate AccessContext with recursive call.
            return authToken;
        } else {
            throw new TokenParseException("peer does not match");
        }
    }
}
