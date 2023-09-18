package org.miniorange.saml;


import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xerces.parsers.DOMParser;
import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.*;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.security.credential.UsageType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MoIDPMetadata {

    private static Log LOGGER = LogFactory.getLog(MoIDPMetadata.class);

    private String metadata;

    private EntityDescriptor entityDescriptor;
    public String entityId;
    private Map<String, String> singleSignOnServices;
    private Map<String, String> singleLogoutServices;
    public  List<String> signingCertificates;
    public static String certificate;
    public static String nameIdFormat;

    public MoIDPMetadata(String metadata) {
        String FEATURE = null;
        try {
            if (StringUtils.isNotBlank(metadata) && metadata.trim().startsWith("<") && metadata.trim().endsWith(">")) {
                this.metadata = StringUtils.trimToEmpty(metadata);
                MoSAMLUtils.doBootstrap();
                DOMParser parser = new DOMParser();
                FEATURE = "http://apache.org/xml/features/disallow-doctype-decl";
                parser.setFeature(FEATURE, true);
                FEATURE = "http://xml.org/sax/features/external-general-entities";
                parser.setFeature(FEATURE, false);
                FEATURE = "http://xml.org/sax/features/external-parameter-entities";
                parser.setFeature(FEATURE, false);
                FEATURE = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
                parser.setFeature(FEATURE, false);
                parser.parse(new InputSource(new StringReader(this.metadata)));
                Document document = parser.getDocument();
                Element element = document.getDocumentElement();
                UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
                Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
                XMLObject xmlObj = unmarshaller.unmarshall(element);
                entityDescriptor = (EntityDescriptor) xmlObj;
                IDPSSODescriptor idpssoDescriptor = entityDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);

                if (idpssoDescriptor != null) {
                    entityId = entityDescriptor.getEntityID();
                    LOGGER.debug("EntityID: " + entityId);
                    singleSignOnServices = new HashMap<>();
                    for (SingleSignOnService ssoService : idpssoDescriptor.getSingleSignOnServices()) {
                        String binding = ssoService.getBinding();
                        String location = ssoService.getLocation();

                        if (StringUtils.equals(binding, SAMLConstants.SAML2_REDIRECT_BINDING_URI) || StringUtils
                                .equals(binding, SAMLConstants.SAML2_POST_BINDING_URI)) {
                            LOGGER.debug("SingleSignOnService Binding: " + binding + ", Location: " + location);
                            singleSignOnServices.put(binding, location);
                        }
                    }

                    singleLogoutServices = new HashMap<>();
                    for (SingleLogoutService sloService : idpssoDescriptor.getSingleLogoutServices()) {
                        String binding = sloService.getBinding();
                        String location = sloService.getLocation();
                        if (StringUtils.equals(binding, SAMLConstants.SAML2_REDIRECT_BINDING_URI) || StringUtils
                                .equals(binding, SAMLConstants.SAML2_POST_BINDING_URI)) {
                            LOGGER.debug("SingleLogoutService Binding: " + binding + ", Location: " + location);
                            singleLogoutServices.put(binding, location);
                        }
                    }

                    if(!idpssoDescriptor.getNameIDFormats().isEmpty()) {
                        nameIdFormat = StringUtils.defaultIfBlank(idpssoDescriptor.getNameIDFormats().get(0).getFormat(),
                                "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
                    } else {
                        nameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
                    }
                    signingCertificates = new ArrayList<>();
                    for (KeyDescriptor key : idpssoDescriptor.getKeyDescriptors()) {
                        certificate = null;
                        if (key.getKeyInfo().getX509Datas().size() > 0
                                && key.getKeyInfo().getX509Datas().get(0).getX509Certificates().size() > 0) {
                            certificate = key.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0)
                                    .getValue();
                        }
                        if (StringUtils.isBlank(certificate)) {
                            break;
                        }
                        if (UsageType.UNSPECIFIED.equals(key.getUse())) {
                            if(MoSAMLUtils.isValidPublicCertificate(certificate))
                                signingCertificates.add(certificate);
                        }
                        if (UsageType.SIGNING.equals(key.getUse())) {
                            if(MoSAMLUtils.isValidPublicCertificate(certificate))
                                signingCertificates.add(certificate);
                        }
                    }
                }
            }
        } catch (Throwable t) {
            LOGGER.debug("Exception occurs while parsing metadata xml " + t);
        }
    }

    public String getEntityId() {
        return entityId;
    }

    public Map<String, String> getSingleSignOnServices() {
        return singleSignOnServices;
    }

    public Map<String, String> getSingleLogoutServices() {
        return singleLogoutServices;
    }

    public List<String> getSigningCertificates() {
        return signingCertificates;
    }

}
