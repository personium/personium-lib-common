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

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;

import net.oauth.signature.pem.PEMReader;

/**
 * X509 KeySelector class.
 */
public class X509KeySelector extends KeySelector {

    /**
     * Constructor.
     * @param issuer Token issuer URL
     */
    public X509KeySelector(String issuer) {
        super();
        this.issuer = issuer;
    }

    private String issuer;

    private Map<String, X509Certificate> caCerts = new HashMap<String, X509Certificate>();

    /**
     * Default root CA certificate path.
     */
    public static final String DEFAULT_ROOT_CA_PATH = "x509/personium_ca.crt";

    /**
     * Default server certificate key path.
     */
    public static final String DEFAULT_SERVER_KEY_PATH = "x509/localhost.key";

    /**
     * Default server certificate path.
     */
    public static final String DEFAULT_SERVER_CRT_PATH = "x509/localhost.crt";

    /**
     * X509certificate Type.
     */
    public static final String X509KEY_TYPE = "X.509";

    @SuppressWarnings("rawtypes")
    @Override
    public final KeySelectorResult select(
            final KeyInfo keyInfoToUse,
            final KeySelector.Purpose purpose,
            final AlgorithmMethod method,
            final XMLCryptoContext context) throws KeySelectorException {
        Iterator ki = keyInfoToUse.getContent().iterator();
        while (ki.hasNext()) {
            XMLStructure info = (XMLStructure) ki.next();
            if (!(info instanceof X509Data)) {
                continue;
            }
            X509Data x509Data = (X509Data) info;
            Iterator xi = x509Data.getContent().iterator();
            while (xi.hasNext()) {
                Object o = xi.next();
                if (!(o instanceof X509Certificate)) {
                    continue;
                }
                X509Certificate x509Certificate = (X509Certificate) o;
                final PublicKey key = x509Certificate.getPublicKey();
                // Make sure the algorithm is compatible
                // with the method.
                if (algEquals(method.getAlgorithm(), key.getAlgorithm())) {
                    // x509 certificate validation
                    cheakX509validate(x509Certificate);
                    return new KeySelectorResult() {
                        @Override
                        public Key getKey() {
                            return key;
                        }
                    };
                }
            }
        }
        throw new KeySelectorException("No key found!");
    }
    /*
     * true if given two algorithms are identical.
     * @param algURI
     * @param algName
     */
    static boolean algEquals(final String algURI, final String algName) {
        return  ((algName.equalsIgnoreCase("DSA") && algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1)) //NOPMD
                || (algName.equalsIgnoreCase("RSA") && algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1))); //NOPMD
    }

    /**
     * x509 certificate validation.
     * @param certificate x509certificate
     * @throws KeySelectorException KeySelectorException
     */
    private void cheakX509validate(X509Certificate certificate) throws KeySelectorException {

        // Issuer (need validation)
        String issuerDn = certificate.getIssuerX500Principal().getName();

        // Subject(CN=)
        Map<String, Object> map = new HashMap<String, Object>();
        String subjectDn = certificate.getSubjectX500Principal().getName();
        // Example) 1.2.840.113549.1.9.1=#1603706373,CN=pcs,OU=pcs,O=pcs,L=pcs,ST=pcs,C=JP
        String[] pvs = subjectDn.split(",");
        for (int i = 0; i < pvs.length; i++) {
            String[] pv = pvs[i].split("=");
            if (pv.length == 2) {
                map.put(pv[0].toUpperCase().trim(), pv[1].trim());
            }
        }
        String cnStr = (String) map.get("CN");

        // get domain name form issuer
        URL issureUrl = null;
        try {
            issureUrl = new URL(issuer);
        } catch (MalformedURLException e) {
            throw new KeySelectorException(e.getMessage(), e);
        }
        // backward match to support subdomain (per-cell).
        if (cnStr == null || !issureUrl.getHost().endsWith(cnStr)) {
            // when Token CN and issuer of the root ca certificate do not match
            throw new KeySelectorException("Issuer does not match.");
        }

        // Certificate Validation
        // # 1 # Check for Expiration
        try {
            certificate.checkValidity();
        } catch (CertificateExpiredException e) {
            // When it is expired
            throw new KeySelectorException(e.getMessage(), e);
        } catch (CertificateNotYetValidException e) {
            // When it is not yet valid
            throw new KeySelectorException(e.getMessage(), e);
        }

        //  # 2 #  check if the certificate issuer is in the trused RootCA list
        X509Certificate rootCrt = caCerts.get(issuerDn);
        // exception if not in the list
        if (rootCrt == null) {
            throw new KeySelectorException("CA subject not match.");
        }

        //  # 3 # check the signature of the target certificate, using actual public key of the certificate issuer.
        try {
            PublicKey keyRoot = rootCrt.getPublicKey();
            certificate.verify(keyRoot);
        } catch (NoSuchAlgorithmException e) {
            // When signature algorithm is not supported
            throw new KeySelectorException(e.getMessage(), e);
        } catch (InvalidKeyException e) {
            // When the key is invalid
            throw new KeySelectorException(e.getMessage(), e);
        } catch (NoSuchProviderException e) {
            // When default provider does not exist
            throw new KeySelectorException(e.getMessage(), e);
        } catch (SignatureException e) {
            // When signature error
            throw new KeySelectorException(e.getMessage(), e);
        } catch (CertificateException e) {
            // When 符号化エラー
            throw new KeySelectorException(e.getMessage(), e);
        }
    }
    /**
     * read Root CA certificate.
     * @param rootCaFileName file path of root CA certificate
     * @throws IOException IOException
     * @throws CertificateException CertificateException
     */
    public void readRoot(List<String> rootCaFileName) throws IOException, CertificateException {
        // when no configuration, Use default Root CA certificate
        if (rootCaFileName == null || rootCaFileName.size() == 0) {
            readCaFile(TransCellAccessToken.class.getClassLoader().getResourceAsStream(DEFAULT_ROOT_CA_PATH));
            return;
        }

        // Read root Certificate
        for (String caCertFileName : rootCaFileName) {
            InputStream is = new FileInputStream(caCertFileName);
            readCaFile(is);
        }
    }

    private void readCaFile(InputStream is) throws IOException, CertificateException {
        PEMReader pemReader;
        pemReader = new PEMReader(is);
        byte[] bytesCert = pemReader.getDerBytes();
        CertificateFactory cf = CertificateFactory.getInstance(X509KEY_TYPE);
        X509Certificate x509Root = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytesCert));
        // Check if Root CA Certificate is valid
        x509Root.checkValidity();
        // Check if Root CA Certificate is duplicate
        if (caCerts.get(x509Root.getIssuerX500Principal().getName()) != null) {
            throw new CertificateException("Duplicated ca subject names.");
        }
        caCerts.put(x509Root.getIssuerX500Principal().getName(), x509Root);
    }
}
