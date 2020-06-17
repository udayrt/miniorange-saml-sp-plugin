package org.miniorange.saml;

import jenkins.model.Jenkins;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.util.List;
import java.util.logging.Logger;

public class MoSAMLPluginSettings {

    private String idpEntityId;
    private String ssoUrl;
    private String x509Certificate;
    // Information related to Attribute Mapping
    private String usernameAttribute;
    private String emailAttribute;
   private String nameIDFormat;
   private int noOfUsers=0;
    private static final String PRIVATE_CERT_PATH = "/certificates/sp-key.key";
    public static String PRIVATE_CERTIFICATE = "";
    private static final Logger LOGGER = Logger.getLogger(MoSAMLManager.class.getName());

    static {
        try {

            PRIVATE_CERTIFICATE = IOUtils.toString(MoSAMLPluginSettings.class.getResourceAsStream(PRIVATE_CERT_PATH),
                    "UTF-8");
            PRIVATE_CERTIFICATE = MoSAMLUtils.serializePrivateCertificate(PRIVATE_CERTIFICATE);

        } catch (IOException e) {
            LOGGER.fine("An I/O error occurred while initializing the SAML Settings.");
        }
    }
    public MoSAMLPluginSettings (String idpEntityId, String ssoUrl,  String x509Certificate, String usernameAttribute, String emailAttribute,int noOfUsers, String nameIDFormat) {
        this.idpEntityId = idpEntityId;
        this.ssoUrl = ssoUrl;
        this.x509Certificate = x509Certificate;
        this.usernameAttribute = usernameAttribute;
        this.emailAttribute = emailAttribute;
        this.noOfUsers=noOfUsers;
        this.nameIDFormat= nameIDFormat;
    }

    public String getIdpEntityId() {
        return idpEntityId;
    }

    public String getSsoUrl() { return ssoUrl; }

    public String getX509Certificate() {
        return x509Certificate;
    }

    public String getUsernameAttribute() {
        return usernameAttribute;
    }

    public String getEmailAttribute() {
        return emailAttribute;
    }

    public String getSPBaseUrl() {
        String rootURL= Jenkins.getInstance().getRootUrl();
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
        return getSPBaseUrl() + "securityRealm/moSamlAuth";
    }


    public String getPrivateSPCertificate() { return StringUtils.defaultString(PRIVATE_CERTIFICATE); }

    public String getNameIDFormat() {
        if (org.apache.commons.lang.StringUtils.isEmpty(nameIDFormat)) {
            return "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
        } else {
            return emailAttribute;
        }
    }
}
