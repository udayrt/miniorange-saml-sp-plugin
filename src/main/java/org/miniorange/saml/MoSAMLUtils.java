package org.miniorange.saml;
import org.apache.commons.lang.StringUtils;
import org.jsoup.Jsoup;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.ConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import org.joda.time.DateTime;
import org.opensaml.Configuration;

import org.opensaml.common.SAMLVersion;

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.security.SAMLSignatureProfileValidator;

import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.EncryptedKey;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.io.*;
import org.opensaml.xml.security.credential.Credential;

import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.*;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.net.URLEncoder;

import java.security.KeyFactory;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Iterator;

import java.util.UUID;
import java.util.logging.Logger;
import java.util.zip.*;


public class MoSAMLUtils {
    private static boolean bootstrap = false;
    public static final String SAML_REQUEST_PARAM = "SAMLRequest";
    public static final String RELAY_STATE_PARAM = "RelayState";
    public static final String SIGNATURE_ALGO_PARAM = "SigAlg";
    public static final String SIGNATURE_PARAM = "Signature";
    public static final String SAML_RESPONSE_PARAM = "SAMLResponse";
    private static final Logger LOGGER = Logger.getLogger(MoSAMLUtils.class.getName());

    public static void doBootstrap() {
        if (!bootstrap) {
            try {
                bootstrap = true;
                DefaultBootstrap.bootstrap();
            } catch (ConfigurationException e) {
                System.out.println("error");		}
        }
    }
    public static String sanitizeText(String text) {
        //Removing all the HTML Tags
        if(StringUtils.isBlank(text)){
            return text;
        }
       // LOGGER.fine("Text before sanitization: "+text);
        text = Jsoup.parse(text).text();
       // LOGGER.fine("Text after sanitization: "+text);
        return text;
    }

    public static Response decodeResponse(String encodedResponse) throws Exception {
        LOGGER.fine("Decoding Response..");
        String xml = new String(Base64.decode(encodedResponse), "UTF-8");
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        /** Ignore comments while reading Response : XML Canonicalization Vulnerability  : https://www.kb.cert.org/vuls/id/475445 */
        documentBuilderFactory.setIgnoringComments(true);
        disableExternalEntityParsing(documentBuilderFactory);
        DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
        ByteArrayInputStream is = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
        Document document = docBuilder.parse(is);
        Element element = document.getDocumentElement();
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
        XMLObject xmlObj = unmarshaller.unmarshall(element);
        Response response = (Response) xmlObj;
        return response;
    }
    public static AuthnRequest buildAuthnRequest(String issuer, String acsUrl, String destination, String nameIdFormat, String authnContextClass) {
        LOGGER.fine("Building Authentication Request");
        AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject(SAMLConstants.SAML20P_NS,
                AuthnRequest.DEFAULT_ELEMENT_LOCAL_NAME, "samlp");
        DateTime issueInstant = new DateTime();
        authnRequest.setID(generateRandomString());
        authnRequest.setVersion(SAMLVersion.VERSION_20);
        authnRequest.setIssueInstant(issueInstant);
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        authnRequest.setIssuer(buildIssuer(issuer));
        authnRequest.setAssertionConsumerServiceURL(acsUrl);
        authnRequest.setDestination(destination);
        if(org.apache.commons.lang3.StringUtils.isNotBlank(authnContextClass) && !authnContextClass.equals("None")){
            authnRequest.setRequestedAuthnContext(buildRequestedAuthnContext(authnContextClass));
        }

        //Create NameIDPolicy
        NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
        NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();
        nameIdPolicy.setFormat(nameIdFormat);
        nameIdPolicy.setAllowCreate(true);
        authnRequest.setNameIDPolicy(nameIdPolicy);
        return authnRequest;
    }
    private static Issuer buildIssuer(String issuerValue) {
        LOGGER.fine("Building Issuer");
        Issuer issuer = new IssuerBuilder().buildObject(SAMLConstants.SAML20_NS, Issuer.DEFAULT_ELEMENT_LOCAL_NAME,
                "saml");
        issuer.setValue(issuerValue);
        return issuer;
    }
    public static RequestedAuthnContext buildRequestedAuthnContext(String authnContextClassRefValue){
        /* AuthnContextClass */
        AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
        AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:assertion", "AuthnContextClassRef", "saml");
        authnContextClassRef.setAuthnContextClassRef(authnContextClassRefValue);

        /* RequestedAuthnContext */
        RequestedAuthnContextBuilder requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
        RequestedAuthnContext requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
        requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);

        return requestedAuthnContext;
    }

    public static Assertion decryptAssertion(EncryptedAssertion encryptedAssertion, String publicKey, String privateKey)
            throws CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, DecryptionException {
        LOGGER.fine("Decrypting Assertion.");
        StaticKeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(
                getCredential(publicKey, privateKey));
        Decrypter decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
        Iterator<EncryptedKey> it = decrypter.getEncryptedKeyResolver().resolve(encryptedAssertion.getEncryptedData())
                .iterator();
        if (!it.hasNext()) {
            decrypter = new Decrypter(null, keyInfoCredentialResolver, new EncryptedElementTypeEncryptedKeyResolver());
        }
        decrypter.setRootInNewDocument(true);
        return decrypter.decrypt(encryptedAssertion);
    }
    public static Boolean verifyCertificate(SignableXMLObject response, String certificate)
            throws ValidationException, CertificateException, InvalidKeySpecException, NoSuchAlgorithmException {
        LOGGER.fine("Varifing Certificate");
        if (response.isSigned()) {
            SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
            profileValidator.validate(response.getSignature());
            Credential verificationCredential = getCredential(certificate, "");
            SignatureValidator sigValidator = new SignatureValidator(verificationCredential);
            sigValidator.validate(response.getSignature());
            return Boolean.TRUE;
        } else {
            if (response instanceof Response) {
                LOGGER.fine("Response not Signed");
                throw new MoSAMLException(MoSAMLException.SAMLErrorCode.RESPONSE_NOT_SIGNED);
            } else {
                LOGGER.fine("Assertion not Signed");
                throw new MoSAMLException(MoSAMLException.SAMLErrorCode.ASSERTION_NOT_SIGNED);
            }
        }

    }
    public static String generateRandomString() {
        String uuid = UUID.randomUUID().toString();
        return "_" + org.apache.commons.lang3.StringUtils.remove(uuid, '-');
    }
    private static Credential getCredential(String publicKey, String privateKeyStr)
            throws CertificateException, InvalidKeySpecException, NoSuchAlgorithmException {
        publicKey = serializePublicCertificate(publicKey);
        InputStream is = new ByteArrayInputStream(publicKey.getBytes(StandardCharsets.UTF_8));
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) cf.generateCertificate(is);
        BasicX509Credential x509Credential = new BasicX509Credential();
        x509Credential.setPublicKey(cert.getPublicKey());
        PrivateKey privateKey = getPrivateKey(privateKeyStr);
        if (privateKey != null) {
            x509Credential.setPrivateKey(privateKey);
        }
        Credential credential = x509Credential;
        LOGGER.fine("credential = " + credential);
        return credential;
    }
    public static String serializePublicCertificate(String certificate) {
        LOGGER.fine("Serializing Public Certificate");
        String BEGIN_CERTIFICATE = "BEGIN CERTIFICATE";
        String END_CERTIFICATE = "END CERTIFICATE";
        if (org.apache.commons.lang3.StringUtils.isNotBlank(certificate)) {
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, "\r");
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, "\n");
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, "-");
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, BEGIN_CERTIFICATE);
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, END_CERTIFICATE);
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, " ");
            org.apache.commons.codec.binary.Base64 encoder = new org.apache.commons.codec.binary.Base64(64);
            certificate = encoder.encodeToString(org.apache.commons.codec.binary.Base64.decodeBase64(certificate));
            StringBuffer cert = new StringBuffer("-----" + BEGIN_CERTIFICATE + "-----\r\n");
            cert.append(certificate);
            cert.append("-----" + END_CERTIFICATE + "-----");
            return cert.toString();
        }
        return certificate;
    }

    public static String deserializePublicCertificate(String certificate) {
        LOGGER.fine("Deserializing Public Certificate");
        String BEGIN_CERTIFICATE = "BEGIN CERTIFICATE";
        String END_CERTIFICATE = "END CERTIFICATE";
        if (org.apache.commons.lang3.StringUtils.isNotBlank(certificate)) {
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, "\r");
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, "\n");
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, "-");
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, BEGIN_CERTIFICATE);
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, END_CERTIFICATE);
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, " ");
        }
        return certificate;
    }

    public static String serializePrivateCertificate(String certificate) {
        LOGGER.fine("Serializing Private Certificate");
        String BEGIN_CERTIFICATE = "BEGIN PRIVATE KEY";
        String END_CERTIFICATE = "END PRIVATE KEY";
        if (org.apache.commons.lang3.StringUtils.isNotBlank(certificate)) {
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, "\r");
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, "\n");
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, "-");
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, BEGIN_CERTIFICATE);
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, END_CERTIFICATE);
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, " ");
            org.apache.commons.codec.binary.Base64 encoder = new org.apache.commons.codec.binary.Base64(64);
            certificate = encoder.encodeToString(org.apache.commons.codec.binary.Base64.decodeBase64(certificate));
            StringBuffer cert = new StringBuffer("-----" + BEGIN_CERTIFICATE + "-----\r\n");
            cert.append(certificate);
            cert.append("-----" + END_CERTIFICATE + "-----");
            return cert.toString();
        }
        return certificate;
    }

    public static String deserializePrivateCertificate(String certificate) {
        LOGGER.fine("Deserializing Private Certificate");
        String BEGIN_CERTIFICATE = "BEGIN PRIVATE KEY";
        String END_CERTIFICATE = "END PRIVATE KEY";
        if (org.apache.commons.lang3.StringUtils.isNotBlank(certificate)) {
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, "\r");
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, "\n");
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, "-");
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, BEGIN_CERTIFICATE);
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, END_CERTIFICATE);
            certificate = org.apache.commons.lang3.StringUtils.remove(certificate, " ");
        }
        return certificate;
    }

    public static Boolean isValidCertificate(String certificate) {
        LOGGER.fine("Validating Certificate");
        certificate = serializePublicCertificate(certificate);
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) cf
                    .generateCertificate(new ByteArrayInputStream(certificate.getBytes(StandardCharsets.UTF_8)));
            return Boolean.TRUE;
        } catch (CertificateException e) {
            return Boolean.FALSE;
        }
    }
    public static String base64EncodeRequest(XMLObject request, Boolean isHttpPostBinding) throws Exception {
        LOGGER.fine("Encoding Sign Request with Base64 encoder.");
        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(request);
        LOGGER.fine("Encoding Sign Request with Base64 encoder.1");
        Element authDOM = marshaller.marshall(request);
        LOGGER.fine("Encoding Sign Request with Base64 encoder.2");
        // DOM to string
        StringWriter requestWriter = new StringWriter();
        LOGGER.fine("Encoding Sign Request with Base64 encoder.3");
        XMLHelper.writeNode(authDOM, requestWriter);
        LOGGER.fine("Encoding Sign Request with Base64 encoder.4");
        String requestMessage = requestWriter.toString();
        LOGGER.fine("HTTP-Redirect Binding selected for SSO1");
        if (isHttpPostBinding) {
            String authnRequestStr = Base64.encodeBytes(requestMessage.getBytes(StandardCharsets.UTF_8), Base64.DONT_BREAK_LINES);
            return authnRequestStr;
        }
        // compressing
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
        deflaterOutputStream.write(requestMessage.getBytes(StandardCharsets.UTF_8));
        deflaterOutputStream.close();
        LOGGER.fine("HTTP-Redirect Binding selected for SSO2");
        byteArrayOutputStream.close();
        String encodedRequestMessage = Base64.encodeBytes(byteArrayOutputStream.toByteArray(), Base64.DONT_BREAK_LINES);
        return encodedRequestMessage;
    }
    public static String signHttpRedirectRequest(String requestQueryString, String sigAlgo, String pubicKey,
                                                 String privateKey) throws Exception {
        LOGGER.fine("Signig Http Redirect Request called ");
        StringBuilder builder = new StringBuilder(requestQueryString);
        builder.append("&").append(SIGNATURE_ALGO_PARAM).append("=").append(URLEncoder.encode(sigAlgo, "UTF-8"));
        Signature signature = Signature.getInstance("SHA256withRSA");
        Credential credentials = getCredential(pubicKey, privateKey);
        signature.initSign(credentials.getPrivateKey());
        signature.update(builder.toString().getBytes(StandardCharsets.UTF_8));
        byte[] signatureByteArray = signature.sign();
        String signatureBase64encodedString = Base64.encodeBytes(signatureByteArray);
        // builder.append("&").append(SIGNATURE_PARAM).append("=").append(URLEncoder.encode(signatureBase64encodedString,
        // "UTF-8").trim());
        return signatureBase64encodedString;
    }

    private static void disableExternalEntityParsing(DocumentBuilderFactory dbf){
        LOGGER.info("Disabling External Entity Parsing from DocumentBuilderFactory");
        String FEATURE = null;
        try {
            // This is the PRIMARY defense. If DTDs (doctypes) are disallowed, almost all XML entity attacks are prevented
            // Xerces 2 only - http://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl
            FEATURE = "http://apache.org/xml/features/disallow-doctype-decl";
            dbf.setFeature(FEATURE, true);

            // If you can't completely disable DTDs, then at least do the following:
            // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-general-entities
            // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-general-entities
            // JDK7+ - http://xml.org/sax/features/external-general-entities
            FEATURE = "http://xml.org/sax/features/external-general-entities";
            dbf.setFeature(FEATURE, false);

            // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-parameter-entities
            // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-parameter-entities
            // JDK7+ - http://xml.org/sax/features/external-parameter-entities
            FEATURE = "http://xml.org/sax/features/external-parameter-entities";
            dbf.setFeature(FEATURE, false);

            // Disable external DTDs as well
            FEATURE = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
            dbf.setFeature(FEATURE, false);

            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);

        } catch (ParserConfigurationException e) {
            // This should catch a failed setFeature feature
            LOGGER.fine("ParserConfigurationException was thrown. The feature '" +
                    FEATURE + "' is probably not supported by your XML processor.");
        }
    }

    private static PrivateKey getPrivateKey(String privateKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        LOGGER.fine("getPrivateKey called ");
        if (org.apache.commons.lang3.StringUtils.isNotBlank(privateKey)) {
            privateKey = deserializePrivateCertificate(privateKey);
            byte[] bytes = Base64.decode(privateKey);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        }
        return null;
    }
    public static Boolean isValidPublicCertificate(String certificate) {
        LOGGER.fine("Validating Public Certificate");
        certificate = serializePublicCertificate(certificate);
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) cf
                    .generateCertificate(new ByteArrayInputStream(certificate.getBytes(StandardCharsets.UTF_8)));
            return Boolean.TRUE;
        } catch (CertificateException e) {
            return Boolean.FALSE;
        }
    }
}
