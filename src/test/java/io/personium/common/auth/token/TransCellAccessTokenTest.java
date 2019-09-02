package io.personium.common.auth.token;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.naming.InvalidNameException;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import io.personium.common.auth.token.AbstractOAuth2Token.TokenDsigException;
import io.personium.common.auth.token.AbstractOAuth2Token.TokenParseException;
import io.personium.common.auth.token.AbstractOAuth2Token.TokenRootCrtException;

public class TransCellAccessTokenTest {
    static final String ISSUER = "https://issuer.localhost/";
    static final String SUBJECT = "https://subject.localhost/#acc";
    static String TARGET = "https://target.localhost/";
    static String SCHEMA = "https://schema.localhost/";
    static String[] SCOPE = new String[] {"auth", "message-read"};
    static List<Role> ROLE_LIST = new ArrayList<>();
    static Set<String> SCOPE_SET = new HashSet<>();
    static {
        try {
            ROLE_LIST.add(new Role(new URL("https://schema.localhost/__role/__/role1")));
            ROLE_LIST.add(new Role(new URL("https://schema.localhost/__role/__/role2")));
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
    }

    TransCellAccessToken token;
    @Before
    public void setUp() throws Exception {
        String keyPath = ClassLoader.getSystemResource("x509/localhost.key").getPath();
        String crtPath = ClassLoader.getSystemResource("x509/localhost.crt").getPath();
        String cacPath = ClassLoader.getSystemResource("x509/personium_ca.crt").getPath();
        //URL r = c.getResource("x509/localhost.key");
        try {

            TransCellAccessToken.configureX509(keyPath, crtPath, new String[] {cacPath});
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | CertificateException | InvalidNameException
                | IOException e) {
            e.printStackTrace();
        }
        this.token = new TransCellAccessToken(new Date().getTime(),
                AbstractOAuth2Token.ACCESS_TOKEN_EXPIRES_MILLISECS,
                ISSUER,
                SUBJECT,
                TARGET,
                ROLE_LIST,
                SCHEMA, SCOPE);
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void testParse_issuer_subject_schema() throws TokenParseException, TokenDsigException, TokenRootCrtException {
        String tokenStr = this.token.toTokenString();
        TransCellAccessToken token2 = TransCellAccessToken.parse(tokenStr);
        assertEquals(ISSUER, token2.getIssuer());
        assertEquals(SUBJECT, token2.getSubject());
        assertEquals(SCHEMA, token2.getSchema());
    }
    @Test
    public void testParse_scopes() throws TokenParseException, TokenDsigException, TokenRootCrtException {
        String tokenStr = this.token.toTokenString();
        TransCellAccessToken token2 = TransCellAccessToken.parse(tokenStr);
        assertEquals(SCOPE.length, token2.getScope().length);
    }

    @Test
    public void testParse_roles() throws TokenParseException, TokenDsigException, TokenRootCrtException {
        String tokenStr = this.token.toTokenString();
        TransCellAccessToken token2 = TransCellAccessToken.parse(tokenStr);
        List<Role> parsedRoles = token2.getRoleList();
        assertEquals(ROLE_LIST.size(), parsedRoles.size());
        StringBuilder sb1 = new StringBuilder();
        for (Role role : ROLE_LIST) {
            sb1.append(role.getBoxSchema() + ":" +role.getName());
            sb1.append(" ");
        }
        StringBuilder sb2 = new StringBuilder();
        for (Role role : parsedRoles) {
            sb2.append(role.getBoxSchema() + ":" +role.getName());
            sb2.append(" ");
        }
        assertEquals(sb1.toString(), sb2.toString());
    }

    @Test
    public void print() throws TokenParseException, TokenDsigException, TokenRootCrtException {
        System.out.println(this.token.toSamlString());
    }


}
