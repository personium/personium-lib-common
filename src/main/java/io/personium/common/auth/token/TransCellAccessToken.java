/**
 * Personium
 * Copyright 2014-2022 Personium Project Authors
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
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.lang.CharEncoding;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import io.personium.common.utils.CommonUtils;
import net.oauth.signature.pem.PEMReader;
import net.oauth.signature.pem.PKCS1EncodedKeySpec;

/**
 * Class for handling Trans-Cell access token.
 */
@SuppressWarnings({ "unchecked", "rawtypes" })
public final class TransCellAccessToken extends AbstractOAuth2Token implements IAccessToken, IExtRoleContainingToken {


    private static final String URN_OASIS_NAMES_TC_SAML_2_0_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";

    /**
     * logger.
     */
    static Logger log = LoggerFactory.getLogger(TransCellAccessToken.class);
    private static List<String> x509RootCertificateFileNames;
    private static XMLSignatureFactory xmlSignatureFactory;
    private static X509Certificate x509Certificate;
    private static KeyInfo keyInfo;
    private static PrivateKey privKey;
    private SignedInfo signedInfo;
    public static SignedInfo createSignedInfo() {
        try {
            /*
             * creates the Reference object, which identifies the data that will be digested and signed. The Reference
             * object is assembled by creating and passing as parameters each of its components: the URI, the
             * DigestMethod, and a list of Transforms
             */
            DigestMethod digestMethod = xmlSignatureFactory.newDigestMethod(DigestMethod.SHA256, null);
            Transform transform = xmlSignatureFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
            Reference reference = xmlSignatureFactory.newReference("", digestMethod,
                    Collections.singletonList(transform), null, null);

            /*
             * creates the SignedInfo object that the signature is calculated over. Like the Reference object, the
             * SignedInfo object is assembled by creating and passing as parameters each of its components: the
             * CanonicalizationMethod, the SignatureMethod, and a list of References
             */
            CanonicalizationMethod c14nMethod = xmlSignatureFactory.newCanonicalizationMethod(
                    CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);
            SignatureMethod signatureMethod = xmlSignatureFactory.newSignatureMethod(SignatureMethod.RSA_SHA256, null);
            return xmlSignatureFactory.newSignedInfo(c14nMethod, signatureMethod,
                    Collections.singletonList(reference));

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            // This should not happen
            throw new RuntimeException(e);
        }
    }

    String id;
    String target;


    /**
     * Constructor.
     * @param id identifier for this token (SAML assertion)
     * @param issuedAt token issue time (millisec from the epoch)
     * @param lifespan Token lifespan (Millisec)
     * @param issuer Issuer Cell URL
     * @param subject access Subject URL
     * @param target target URL
     * @param roleList Role class List assigned at issuer Cell
     * @param schema client authenthenticated
     * @param scope scopes of the token
     */
    public TransCellAccessToken(final String id,
            final long issuedAt,
            final long lifespan,
            final String issuer,
            final String subject,
            final String target,
            final List<Role> roleList,
            final String schema,
            final String[] scope) {
        this.issuedAt = issuedAt;
        this.lifespan = lifespan;
        this.id = id;
        this.issuer = issuer;
        this.subject = subject;
        this.target = target;
        this.roleList = roleList;
        this.schema = schema;
        this.scope = scope;

        this.signedInfo = createSignedInfo();
    }

    /**
     * Constructor.
     * @param id identifier for this token (SAML assertion)
     * @param issuedAt token issue time (millisec from the epoch)
     * @param issuer Issuer Cell URL
     * @param subject access Subject URL
     * @param target target URL
     * @param roleList Role class List assigned at issuer Cell
     * @param schema client authenthenticated
     * @param scope scopes of the token
     */
    public TransCellAccessToken(final String id,
            final long issuedAt,
            final String issuer,
            final String subject,
            final String target,
            final List<Role> roleList,
            final String schema,
            final String[] scope) {
        this(id, issuedAt, ACCESS_TOKEN_EXPIRES_MILLISECS, issuer, subject, target, roleList, schema, scope);
    }

    /**
     * Constructor with automatic ID assignation with an UUID.
     * @param issuer Issuer Cell URL
     * @param subject access Subject URL
     * @param target target URL
     * @param roleList Role class List assigned at issuer Cell
     * @param schema client authenthenticated
     * @param scope scopes of the token
     */
    public TransCellAccessToken(
            final String issuer,
            final String subject,
            final String target,
            final List<Role> roleList,
            final String schema,
            final String[] scope) {
        this(UUID.randomUUID().toString(), new Date().getTime(), issuer, subject, target, roleList, schema, scope);
    }

    /**
     * Constructor with automatic ID assignation with an UUID.
     * @param issuedAt token issue time (millisec from the epoch)
     * @param issuer Issuer Cell URL
     * @param subject access Subject URL
     * @param target target URL
     * @param roleList Role class List assigned at issuer Cell
     * @param schema client authenthenticated
     * @param scope scopes of the token
     */
    public TransCellAccessToken(
            final long issuedAt,
            final String issuer,
            final String subject,
            final String target,
            final List<Role> roleList,
            final String schema,
            final String[] scope) {
        this(UUID.randomUUID().toString(), issuedAt, issuer, subject, target, roleList, schema, scope);
    }

    /**
     * constructor with automatic ID assignation with an UUID.
     * @param issuedAt token issue time (millisec from the epoch)
     * @param lifespan token lifespan (in millisec)
     * @param issuer Issuer Cell URL
     * @param subject access Subject URL
     * @param target target URL
     * @param roleList Role class List assigned at issuer Cell
     * @param schema client authenthenticated
     * @param scope scopes of the token
     */
    public TransCellAccessToken(
            final long issuedAt,
            final long lifespan,
            final String issuer,
            final String subject,
            final String target,
            final List<Role> roleList,
            final String schema,
            final String[] scope) {
        this(UUID.randomUUID().toString(), issuedAt, lifespan, issuer, subject, target, roleList, schema, scope);
    }

    /* (non-Javadoc)
     * @see io.personium.core.auth.token.AbstractOAuth2Token#toTokenString()
     */
    @Override
    public String toTokenString() {
        String samlStr = this.toSamlString();
        try {
            // encode with Base64url
            String token = CommonUtils.encodeBase64Url(samlStr.getBytes(CharEncoding.UTF_8));
            return token;
        } catch (UnsupportedEncodingException e) {
            // Should never come here. never be unable to understand UTF8
            throw new RuntimeException(e);
        }
    }

    /**
     * create a SAML String from this token.
     * @return SAML String
     */
    public String toSamlString() {

        /*
         * Creation of SAML2.0 Document
         * http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
         */

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder builder = null;
        try {
            builder = dbf.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            // Should never happen
            throw new RuntimeException(e);
        }
        Document doc = builder.newDocument();
        Element assertion = doc.createElementNS(URN_OASIS_NAMES_TC_SAML_2_0_ASSERTION, "Assertion");
        doc.appendChild(assertion);
        assertion.setAttribute("ID", this.id);
        assertion.setAttribute("Version", "2.0");

        // Dummy Date
        DateTime dateTime = new DateTime(this.issuedAt);

        assertion.setAttribute("IssueInstant", dateTime.toString());

        DateTime notOnOrAfterDateTime = new DateTime(this.issuedAt + this.lifespan);

        // Issuer
        Element issuer = doc.createElement("Issuer");
        issuer.setTextContent(this.issuer);
        assertion.appendChild(issuer);

        // Subject
        Element subject = doc.createElement("Subject");
        Element nameId = doc.createElement("NameID");
        nameId.setTextContent(this.subject);
        Element subjectConfirmation = doc.createElement("SubjectConfirmation");
        subjectConfirmation.setAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer");
        Element subjectConfirmationData = doc.createElement("SubjectConfirmationData");
        subjectConfirmationData.setAttribute("NotOnOrAfter", notOnOrAfterDateTime.toString());
        subjectConfirmationData.setAttribute("Recipient", this.target + "__token");
        subjectConfirmation.appendChild(subjectConfirmationData);
        subject.appendChild(nameId);
        subject.appendChild(subjectConfirmation);
        assertion.appendChild(subject);

        // Conditions
        Element conditions = doc.createElement("Conditions");
        Element audienceRestriction = doc.createElement("AudienceRestriction");
        for (String aud : new String[] {this.target, this.schema}) {
            Element audience = doc.createElement("Audience");
            audience.setTextContent(aud);
            audienceRestriction.appendChild(audience);
        }
        conditions.appendChild(audienceRestriction);
        assertion.appendChild(conditions);

        // AuthnStatement
        Element authnStmt = doc.createElement("AuthnStatement");
        authnStmt.setAttribute("AuthnInstant", dateTime.toString());
        Element authnCtxt = doc.createElement("AuthnContext");
        Element authnCtxtCr = doc.createElement("AuthnContextClassRef");
        authnCtxtCr.setTextContent("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
        authnCtxt.appendChild(authnCtxtCr);
        authnStmt.appendChild(authnCtxt);
        assertion.appendChild(authnStmt);

        // AttributeStatement
        Element attrStmt = doc.createElement("AttributeStatement");
        // this fails
        //attrStmt.setAttribute("xmlns:xsi", CommonUtils.XmlConst.NS_XML_SCHEMA_INSTANCE);

        // -- Roles
        Element attributeRoles = doc.createElement("Attribute");
        attributeRoles.setAttribute("Name", "Roles");
        attributeRoles.setAttribute("NameFormat", CommonUtils.XmlConst.NS_PERSONIUM);
        if (this.roleList != null) {
            for (Role role : this.roleList) {
                Element attrValue = doc.createElement("AttributeValue");
                //Attr attr = doc.createAttributeNS(CommonUtils.XmlConst.NS_XML_SCHEMA_INSTANCE, "type");
                //attr.setPrefix("xsi");
                //attr.setValue("string");
                //attrValue.setAttributeNodeNS(attr);
                attrValue.setTextContent(role.toRoleClassURL());
                attributeRoles.appendChild(attrValue);
            }
        }
        attrStmt.appendChild(attributeRoles);

        // -- Scopes
        Element attributeScopes = doc.createElement("Attribute");
        attributeScopes.setAttribute("Name", "Scopes");
        attributeRoles.setAttribute("NameFormat", CommonUtils.XmlConst.NS_PERSONIUM);
        if (this.getScope() != null) {
            for (String scope : this.getScope()) {
                Element attrValue = doc.createElement("AttributeValue");
                //Attr attr = doc.createAttributeNS(CommonUtils.XmlConst.NS_XML_SCHEMA_INSTANCE, "type");
                //attr.setPrefix("xsi");
                //attr.setValue("string");
                //attrValue.setAttributeNodeNS(attr);
                attrValue.setTextContent(scope);
                attributeScopes.appendChild(attrValue);
            }
        }
        attrStmt.appendChild(attributeScopes);
        assertion.appendChild(attrStmt);


        // Normalization
        doc.normalizeDocument();

        // add a Dsig (Digital Signature)
        // Create a DOMSignContext and specify the RSA PrivateKey and
        // location of the resulting XMLSignature's parent element.
        DOMSignContext dsc = new DOMSignContext(privKey, doc.getDocumentElement());

        // Create the XMLSignature, but don't sign it yet.
        XMLSignature signature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo);

        // Marshal, generate, and sign the enveloped signature.
        try {
            signature.sign(dsc);
            // Make it to a string and return
            return CommonUtils.nodeToString(doc.getDocumentElement());
        } catch (MarshalException | XMLSignatureException e1) {
            // Should never happen
            throw new RuntimeException(e1);
        }

        /*
         * ------------------------------------------------------------
         * http://tools.ietf.org/html/draft-ietf-oauth-saml2-bearer-10
         * ------------------------------------------------------------ 2.1. Using SAML Assertions as Authorization
         * Grants To use a SAML Bearer Assertion as an authorization grant, use the following parameter values and
         * encodings. The value of "grant_type" parameter MUST be "urn:ietf:params:oauth:grant-type:saml2-bearer" The
         * value of the "assertion" parameter MUST contain a single SAML 2.0 Assertion. The SAML Assertion XML data MUST
         * be encoded using base64url, where the encoding adheres to the definition in Section 5 of RFC4648 [RFC4648]
         * and where the padding bits are set to zero. To avoid the need for subsequent encoding steps (by "application/
         * x-www-form-urlencoded" [W3C.REC-html401-19991224], for example), the base64url encoded data SHOULD NOT be
         * line wrapped and pad characters ("=") SHOULD NOT be included.
         */
    }

    /**
     * parse a TransCellAccessToken and create an object.
     * @param token Token String
     * @return TransCellAccessToken object (succeeded in parsing)
     * @throws AbstractOAuth2Token.TokenParseException when failed to parse
     * @throws AbstractOAuth2Token.TokenDsigException when failed to vaildate the signature of the certificate
     * @throws AbstractOAuth2Token.TokenRootCrtException when failed to validate Root CA Certificate
     */
    public static TransCellAccessToken parse(final String token) throws AbstractOAuth2Token.TokenParseException,
    AbstractOAuth2Token.TokenDsigException, AbstractOAuth2Token.TokenRootCrtException {
        try {
            byte[] samlBytes = CommonUtils.decodeBase64Url(token);
            ByteArrayInputStream bais = new ByteArrayInputStream(samlBytes);
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder builder = null;
            try {
                builder = dbf.newDocumentBuilder();
            } catch (ParserConfigurationException e) {
                // This should not happen
                throw new RuntimeException(e);
            }

            Document doc = builder.parse(bais);

            Element assertion = doc.getDocumentElement();
            Element issuer = (Element) (doc
                .getElementsByTagNameNS(URN_OASIS_NAMES_TC_SAML_2_0_ASSERTION, "Issuer").item(0));
            Element subject = (Element) (assertion
                .getElementsByTagNameNS(URN_OASIS_NAMES_TC_SAML_2_0_ASSERTION, "Subject").item(0));
            Element subjectNameID = (Element) (subject
                .getElementsByTagNameNS(URN_OASIS_NAMES_TC_SAML_2_0_ASSERTION, "NameID").item(0));
            String id = assertion.getAttribute("ID");
            String issuedAtStr = assertion.getAttribute("IssueInstant");

            DateTime dt = new DateTime(issuedAtStr);

            Element sc = (Element) (subject
                .getElementsByTagNameNS(URN_OASIS_NAMES_TC_SAML_2_0_ASSERTION, "SubjectConfirmation").item(0));
            Element scd = (Element) (sc
                .getElementsByTagNameNS(URN_OASIS_NAMES_TC_SAML_2_0_ASSERTION, "SubjectConfirmationData").item(0));
            String notOnOrAfterStr = scd
                .getAttribute("NotOnOrAfter");
            long lifespan = ACCESS_TOKEN_EXPIRES_MILLISECS;
            if (notOnOrAfterStr != null && !notOnOrAfterStr.isEmpty()) {
                DateTime notOnOrAfterDateTime = new DateTime(notOnOrAfterStr);
                lifespan = notOnOrAfterDateTime.getMillis() - dt.getMillis();
            }

            NodeList audienceList = assertion.getElementsByTagNameNS(URN_OASIS_NAMES_TC_SAML_2_0_ASSERTION, "Audience");
            Element aud1 = (Element) (audienceList.item(0));
            String target = aud1.getTextContent();
            String schema = null;
            if (audienceList.getLength() > 1) {
                Element aud2 = (Element) (audienceList.item(1));
                schema = aud2.getTextContent();
            }

            List<Role> roles = new ArrayList<Role>();
            Set<String> scopes = new HashSet<>();

            NodeList attributeList = assertion
                .getElementsByTagNameNS(URN_OASIS_NAMES_TC_SAML_2_0_ASSERTION, "Attribute");
            for (int i = 0; i < attributeList.getLength(); i++) {
                Element attrElem = (Element) (attributeList.item(i));
                String attrName = attrElem.getAttribute("Name");
                if (attrName == null || "Roles".equals(attrName)) {
                    roles = parseRoles(attrElem);
                } else if ("Scopes".equals(attrName)) {
                    scopes = parseScopes(attrElem);
                }
            }


            NodeList nl = assertion.getElementsByTagNameNS(CommonUtils.XmlConst.NS_XML_DSIG, "Signature");
            if (nl.getLength() == 0) {
                throw new TokenParseException("Cannot find Signature element");
            }
            Element signatureElement = (Element) nl.item(0);

            // Check the Signature validity. 以下の例外はTokenDsigException（署名検証エラー）
            // Create a DOMValidateContext and specify a KeySelector
            // and document context.
            X509KeySelector x509KeySelector = new X509KeySelector(issuer.getTextContent());
            DOMValidateContext valContext = new DOMValidateContext(x509KeySelector, signatureElement);

            // Unmarshal the XMLSignature.
            XMLSignature signature;
            try {
                signature = xmlSignatureFactory.unmarshalXMLSignature(valContext);
            } catch (MarshalException e) {
                throw new TokenDsigException(e.getMessage(), e);
            }

            // read x509 certificate issuer certificate
            try {
                x509KeySelector.readRoot(x509RootCertificateFileNames);
            } catch (CertificateException e) {
                // 500 error since misconfiguration of
                // issuer (root) certificate is a severe problem
                throw new TokenRootCrtException(e.getMessage(), e);
            }

            // Validate the XMLSignature x509 Certificate validation.
            boolean coreValidity;
            try {
                // Workaround for https://bugs.openjdk.java.net/browse/JDK-8017265
                valContext.setIdAttributeNS(assertion, null, "ID");
                coreValidity = signature.validate(valContext);
            } catch (XMLSignatureException e) {
                if (e.getCause().getClass() == new KeySelectorException().getClass()) {
                    throw new TokenDsigException(e.getCause().getMessage(), e.getCause());
                }
                throw new TokenDsigException(e.getMessage(), e);
            }


            // http://www.w3.org/TR/xmldsig-core/#sec-CoreValidation

            // Check core validation status.
            if (!coreValidity) {
                // Signature validation
                boolean isDsigValid;
                try {
                    isDsigValid = signature.getSignatureValue().validate(valContext);
                } catch (XMLSignatureException e) {
                    throw new TokenDsigException(e.getMessage(), e);
                }
                if (!isDsigValid) {
                    throw new TokenDsigException("Failed signature validation");
                }

                // Reference validation
                Iterator i = signature.getSignedInfo().getReferences().iterator();
                for (int j = 0; i.hasNext(); j++) {
                    boolean refValid;
                    try {
                        refValid = ((Reference) i.next()).validate(valContext);
                    } catch (XMLSignatureException e) {
                        throw new TokenDsigException(e.getMessage(), e);
                    }
                    if (!refValid) {
                        throw new TokenDsigException("Failed to validate reference [" + j + "]");
                    }
                }
                throw new TokenDsigException("Signature failed core validation. unkwnon reason.");
            }
            return new TransCellAccessToken(id, dt.getMillis(), lifespan, issuer.getTextContent(),
                    subjectNameID.getTextContent(), target, roles, schema, scopes.toArray(new String[0]));
        } catch (UnsupportedEncodingException e) {
            throw new TokenParseException(e.getMessage(), e);
        } catch (SAXException e) {
            throw new TokenParseException(e.getMessage(), e);
        } catch (IOException e) {
            throw new TokenParseException(e.getMessage(), e);
        }
    }
    private static List<Role> parseRoles(Element e) throws MalformedURLException, DOMException {
        List<Role> ret = new ArrayList<>();
        NodeList attrList = e.getElementsByTagName("AttributeValue");
        for (int i = 0; i < attrList.getLength(); i++) {
            Element attv = (Element) (attrList.item(i));
            ret.add(Role.createFromRoleClassUrl(attv.getTextContent()));
        }

        return ret;
    }
    private static Set<String> parseScopes(Element e) {
        Set<String> ret = new HashSet<>();
        NodeList attrList = e.getElementsByTagName("AttributeValue");
        for (int i = 0; i < attrList.getLength(); i++) {
            Element attv = (Element) (attrList.item(i));
            ret.add(attv.getTextContent());
        }
        return ret;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getTarget() {
        return this.target;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getId() {
        return this.id;
    }

    /**
     * configure X509.
     * @param privateKeyFileName private key file name
     * @param certificateFileName certificate file name
     * @param rootCertificateFileNames root (issuer) certificate file name
     * @throws IOException IOException
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws InvalidKeySpecException InvalidKeySpecException
     * @throws CertificateException CertificateException
     * @throws InvalidNameException InvalidNameException
     */
    public static void configureX509(String privateKeyFileName, String certificateFileName,
            String[] rootCertificateFileNames)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException,
                    InvalidNameException {

        xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM");

        // Read RootCA Certificate
        x509RootCertificateFileNames = new ArrayList<String>();
        if (rootCertificateFileNames != null) {
            for (String fileName : rootCertificateFileNames) {
                x509RootCertificateFileNames.add(fileName);
            }
        }

        // Read Private Key
        InputStream is = null;
        if (privateKeyFileName == null) {
            is = TransCellAccessToken.class.getClassLoader().getResourceAsStream(
                    X509KeySelector.DEFAULT_SERVER_KEY_PATH);
        } else {
            is = new FileInputStream(privateKeyFileName);
        }

        PEMReader privateKeyPemReader = new PEMReader(is);
        byte[] privateKeyDerBytes = privateKeyPemReader.getDerBytes();
        PKCS1EncodedKeySpec keySpecRSAPrivateKey = new PKCS1EncodedKeySpec(privateKeyDerBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        privKey = keyFactory.generatePrivate(keySpecRSAPrivateKey.getKeySpec());

        // Read Certificate
        if (certificateFileName == null) {
            is = TransCellAccessToken.class.getClassLoader().getResourceAsStream(
                    X509KeySelector.DEFAULT_SERVER_CRT_PATH);
        } else {
            is = new FileInputStream(certificateFileName);
        }
        PEMReader serverCertificatePemReader;
        serverCertificatePemReader = new PEMReader(is);
        byte[] serverCertificateBytesCert = serverCertificatePemReader.getDerBytes();
        CertificateFactory cf = CertificateFactory.getInstance(X509KeySelector.X509KEY_TYPE);
        x509Certificate = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(serverCertificateBytesCert));

        // Create the KeyInfo containing the X509Data
        KeyInfoFactory keyInfoFactory = xmlSignatureFactory.getKeyInfoFactory();
        List x509Content = new ArrayList();
        x509Content.add(x509Certificate.getSubjectX500Principal().getName());
        x509Content.add(x509Certificate);
        X509Data xd = keyInfoFactory.newX509Data(x509Content);
        keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(xd));

        // Get FQDN from Certificate and set FQDN to PersoniumCoreUtils
        String dn = x509Certificate.getSubjectX500Principal().getName();
        LdapName ln = new LdapName(dn);
        for (Rdn rdn : ln.getRdns()) {
            if (rdn.getType().equalsIgnoreCase("CN")) {
                CommonUtils.setFQDN(rdn.getValue().toString());
                break;
            }
        }

        // http://java.sun.com/developer/technicalArticles/xml/dig_signature_api/

    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getExtCellUrl() {
        return this.getIssuer();
    }

    @Override
    public String getCookieString(String cookiePeer, String issuer) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String[] getScope() {
        return this.scope;
    }
}
