/**
 * Personium
 * Copyright 2019 Personium Project
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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
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
    static final int IV_BYTE_LENGTH = 16;

    private static byte[] keyBytes;
    private static SecretKey aesKey;

    public static class Type {
        public static class AccessToken {
            public static int SELF_LOCAL = 0;
            public static int VISITOR_LOCAL = 1;
            public static int TRANC_CELL = 2;
            public static int UNIT_LOCLAL_UNIT_USER = 3;
            public static int PASSWORDCHANGE = 4;
        }
        public static class RefreshToken {
            public static int RESIDENT = 3;
            public static int VISITOR = 4;
        }
        public static int GRANT_CODE = 5;
    }

    /**
     * Key文字列を設定します。
     * @param keyString キー文字列.
     */
    public static void setKeyString(String keyString) {
        keyBytes = keyString.getBytes(); // 16/24/32バイトの鍵バイト列
        aesKey = new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Default Constructor.
     */
    protected AbstractLocalToken() {
    }


    /**
     * 明示的な有効期間を設定してトークンを生成する.
     * @param issuedAt 発行時刻(epochからのミリ秒)
     * @param lifespan 有効時間(ミリ秒)
     * @param issuer 発行者
     * @param subject 主体
     * @param schema スキーマ
     */
    public AbstractLocalToken(final long issuedAt, final long lifespan, final String issuer,
             final String subject, final String schema, String scope) {
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


        // 発行時刻のEpochからのミリ秒を逆順にした文字列が先頭から入るため、推測しづらい。
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
            raw.append(this.scope);
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
     * パース処理.
     * パース結果のフィールド数がnumFieldsと一致すること.
     * パース結果のissuerがissuerと一致すること.
     * @param token トークン
     * @param issuer 発行者
     * @param numFields フィールド数
     * @return パースされたトークン
     * @throws AbstractOAuth2Token.TokenParseException トークン解釈に失敗したとき
     */
    static String[] doParse(final String token, final String issuer,
      final int numFields) throws AbstractOAuth2Token.TokenParseException {
        String tokenDecoded = decode(token, getIvBytes(issuer));

        // need 2nd argument -1 to handle the case where extra frags are empty
        //
        String[] frag = tokenDecoded.split(SEPARATOR, -1);

        // If wrong format, throw exception
        if (!issuer.equals(frag[IDX_ISSUER])) {
            throw AbstractOAuth2Token.PARSE_EXCEPTION;
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
        this.scope =  frag[IDX_SCOPE];
        return Arrays.copyOfRange(frag, 7, frag.length);
    }

    /**
     * 指定のIssuer向けのIV (Initial Vector)を生成して返します.
     * IVとしてissuerの最後の最後の１６文字を逆転させた文字列を用います。
     * これにより、違うIssuerを想定してパースすると、パースに失敗する。
     * @param issuer Issuer URL
     * @return Initial Vector Byte array
     */
    protected static byte[] getIvBytes(final String issuer) {
        try {
            return StringUtils.reverse("123456789abcdefg" + issuer)
                    .substring(0, IV_BYTE_LENGTH).getBytes(CharEncoding.UTF_8);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 文字列を暗号化する.
     * @param in 入力文字列
     * @param ivBytes イニシャルベクトル
     * @return 暗号化された文字列
     */
    public static String encode(final String in, final byte[] ivBytes) {
        // IVに、発行CELLのURL逆順を入れることで、より短いトークンに。
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
     * 復号する.
     * @param in 暗号化文字列
     * @param ivBytes イニシャルベクトル
     * @return 復号された文字列
     * @throws AbstractOAuth2Token.TokenParseException 例外
     */
    public static String decode(final String in, final byte[] ivBytes) throws AbstractOAuth2Token.TokenParseException {
        byte[] inBytes = CommonUtils.decodeBase64Url(in);
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
        } catch (NoSuchAlgorithmException e) {
            throw AbstractOAuth2Token.PARSE_EXCEPTION;
        } catch (NoSuchPaddingException e) {
            throw AbstractOAuth2Token.PARSE_EXCEPTION;
        }
        try {
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(ivBytes));
        } catch (InvalidKeyException e) {
            throw AbstractOAuth2Token.PARSE_EXCEPTION;
        } catch (InvalidAlgorithmParameterException e) {
            throw AbstractOAuth2Token.PARSE_EXCEPTION;
        }
        byte[] plainBytes;
        try {
            plainBytes = cipher.doFinal(inBytes);
        } catch (IllegalBlockSizeException e) {
            throw AbstractOAuth2Token.PARSE_EXCEPTION;
        } catch (BadPaddingException e) {
            throw AbstractOAuth2Token.PARSE_EXCEPTION;
        }
        try {
            return new String(plainBytes, CharEncoding.UTF_8);
        } catch (UnsupportedEncodingException e) {
            throw AbstractOAuth2Token.PARSE_EXCEPTION;
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
