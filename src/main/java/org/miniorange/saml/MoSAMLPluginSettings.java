package org.miniorange.saml;

import jenkins.model.Jenkins;
import org.apache.commons.io.IOUtils;
import java.io.IOException;
import java.util.logging.Logger;

public class MoSAMLPluginSettings {

    private String idpEntityId;
    private String ssoUrl;
    private String publicx509Certificate;
    // Information related to Attribute Mapping
    private String usernameAttribute;
    private String emailAttribute;
    private String nameIDFormat;
    private String sslUrl;
    private String loginType;
    private String regexPattern;
    private Boolean enableRegexPattern;
    private Boolean signedRequest;
    private Boolean userCreate;
    private String  ssoBindingType;
    private String sloBindingType;
    private String fullnameAttribute;
    private Boolean  userAttributeUpdate;
    private String newUserGroup;

    private static final String PRIVATE_CERT_PATH = "/certificates/sp-key.key";
    private static final String PUBLIC_CERT_PATH = "/certificates/sp-certificate.crt";
    public static String PRIVATE_CERTIFICATE = "";
    public static String PUBLIC_CERTIFICATE = "";
    private static final Logger LOGGER = Logger.getLogger(MoSAMLManager.class.getName());

    static {
        try {

            PRIVATE_CERTIFICATE = IOUtils.toString(MoSAMLPluginSettings.class.getResourceAsStream(PRIVATE_CERT_PATH),
                    "UTF-8");
            PRIVATE_CERTIFICATE = MoSAMLUtils.serializePrivateCertificate(PRIVATE_CERTIFICATE);

            PUBLIC_CERTIFICATE = IOUtils.toString(MoSAMLPluginSettings.class.getResourceAsStream(PUBLIC_CERT_PATH),
                    "UTF-8");
            PUBLIC_CERTIFICATE = MoSAMLUtils.serializePublicCertificate(PUBLIC_CERTIFICATE);


        } catch (IOException e) {
            LOGGER.fine("An I/O error occurred while initializing the SAML Settings.");
        }
    }
    public MoSAMLPluginSettings (String idpEntityId, String ssoUrl,  String publicx509Certificate,
                                 String usernameAttribute, String emailAttribute,
                                 String nameIDFormat, String sslUrl, String loginType,
                                 String regexPattern, Boolean enableRegexPattern, Boolean signedRequest,
                                 Boolean userCreate ,String ssoBindingType,String sloBindingType,
                                 String fullnameAttribute, Boolean userAttributeUpdate, String newUserGroup) {
        this.idpEntityId = idpEntityId;
        this.ssoUrl = ssoUrl;
        this.publicx509Certificate = publicx509Certificate;
        this.usernameAttribute = usernameAttribute;
        this.emailAttribute = emailAttribute;
        this.nameIDFormat= nameIDFormat;
        this.sslUrl= sslUrl;
        this.loginType = (loginType != null) ? loginType : "usernameLogin";
        this.regexPattern= regexPattern;
        this.enableRegexPattern= enableRegexPattern;
        this.signedRequest= signedRequest;
        this.userCreate = userCreate;
        this.ssoBindingType= ssoBindingType;
        this.sloBindingType =sloBindingType;
        this.fullnameAttribute= fullnameAttribute;
        this.userAttributeUpdate= userAttributeUpdate;
        this.newUserGroup= newUserGroup;
    }


    public String getIdpEntityId() {
        return idpEntityId;
    }

    public String getSsoUrl() { return ssoUrl; }

    public String getX509PublicCertificate() {
        return publicx509Certificate;
    }

    public String getUsernameAttribute() {
        return usernameAttribute;
    }

    public String getEmailAttribute() {
        return emailAttribute;
    }

    public String getSPBaseUrl() {
        String rootURL= Jenkins.getInstance().getRootUrl();
        if(rootURL.endsWith("/")){
            rootURL= rootURL.substring(0,rootURL.length()-1);
        }
        return rootURL;
    }

    public String getSPEntityID() {
        String rootURL= Jenkins.getInstance().getRootUrl();
        if(rootURL.endsWith("/")){
            rootURL= rootURL.substring(0,rootURL.length()-1);
        }
        return rootURL;
    }

    public String getSPAudienceURI() {
        String rootURL= Jenkins.getInstance().getRootUrl();
        if(rootURL.endsWith("/")){
            rootURL= rootURL.substring(0,rootURL.length()-1);
        }
        return rootURL;
    }

    public String getSpAcsUrl() {
        return getSPBaseUrl() + "/securityRealm/moSamlAuth";
    }

    public String getPrivateSPCertificate() { return MoSAMLUtils.serializePrivateCertificate(PRIVATE_CERTIFICATE); }

    public String getNameIDFormat() { return nameIDFormat; }

    public String getSslUrl() {
        return sslUrl;
    }

    public boolean getSignedRequest() {
        return signedRequest;
    }

    public String getSloBindingType() {
        return sloBindingType;
    }

    public String getLoginType() { return loginType; }

    public String getRegexPattern() {
        return regexPattern;
    }

    public Boolean getEnableRegexPattern() { return enableRegexPattern; }

    public String getOrganizationName() { return "Xecurify"; }

    public String getOrganizationDisplayName() { return "Xecurify"; }

    public String getOrganizationUrl() { return "http://miniorange.com"; }

    public String getTechnicalContactName() { return "Xecurify"; }

    public String getTechnicalContactEmail() { return "info@xecurify.com"; }

    public String getSupportContactName() { return "Xecurify"; }

    public String getSupportContactEmail() { return "info@xecurify.com"; }

    public Boolean getUserCreate() { return userCreate; }

    public String getPublicSPCertificate(){ return MoSAMLUtils.serializePublicCertificate(PUBLIC_CERTIFICATE); }

    public String getSsoBindingType() { return ssoBindingType; }

    public String getFullnameAttribute() { return fullnameAttribute; }

    public Boolean getUserAttributeUpdate() { return userAttributeUpdate; }


    public String getspSLOURL() {
        return getSPBaseUrl() + "/securityRealm/logout";
    }

    public String getNewUserGroup() {
        return newUserGroup;
    }


}
