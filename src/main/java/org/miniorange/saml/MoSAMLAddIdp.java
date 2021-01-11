package org.miniorange.saml;

import hudson.Util;
import org.acegisecurity.Authentication;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import org.acegisecurity.*;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.userdetails.UserDetails;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.BooleanUtils;

import org.json.JSONException;
import org.json.JSONObject;
import org.kohsuke.stapler.*;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.apache.commons.io.IOUtils;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MediaType;

import javax.servlet.http.HttpSession;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;


import java.nio.charset.StandardCharsets;
import java.util.*;

import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.acegisecurity.BadCredentialsException;
import hudson.tasks.Mailer;

import org.opensaml.saml2.metadata.*;
import org.opensaml.saml2.metadata.impl.*;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.impl.KeyInfoBuilder;
import org.opensaml.xml.signature.impl.X509CertificateBuilder;
import org.opensaml.xml.signature.impl.X509DataBuilder;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import static jenkins.model.Jenkins.get;


public class MoSAMLAddIdp extends SecurityRealm {

    private static final Logger LOGGER = Logger.getLogger(MoSAMLAddIdp.class.getName());
    public static final String MO_SAML_SP_AUTH_URL = "securityRealm/moSamlAuth";
    public static final String MO_SAML_JENKINS_LOGIN_ACTION = "securityRealm/moLoginAction";
    public static final String MO_SAML_SSO_FORCE_STOP = "securityRealm/moSAMLSingleSignOnForceStop";
    public static final String MO_SAML_SP_METADATA_URL = "securityRealm/mospmetadata";
    public static final String MO_SAML_SP_CERTIFCATE_DOWNLOAD = "securityRealm/downloadCertificate";

    public static final String MO_SAML_SSO_LOGIN_ACTION = "securityRealm/moSamlLogin";


    private static final String LOGIN_TEMPLATE_PATH = "/templates/mosaml_login_page_template.html";
    private static final String AUTO_REDIRECT_TO_IDP_TEMPLATE_PATH = "/templates/AutoRedirectToIDPTemplate.html";
    private static final String REFERER_ATTRIBUTE = MoSAMLAddIdp.class.getName() + ".referer";



    private final String idpEntityId;
    private final String ssoUrl;

    private final String publicx509Certificate;
    private final String usernameAttribute;
    private final String fullnameAttribute;
    private final Boolean userAttributeUpdate;
    private final String emailAttribute;
    private final String nameIDFormat;
    private final String sslUrl;
    private final String loginType;
    private final String regexPattern;
    private final Boolean enableRegexPattern;
    private final Boolean signedRequest;
    private final Boolean userCreate;
    private final String ssoBindingType;
    private final String sloBindingType;
    private final Boolean disableDefaultLogin;
    private String newUserGroup;


    @DataBoundConstructor
    public MoSAMLAddIdp(String idpEntityId,
                        String ssoUrl,
                        String publicx509Certificate,
                        String usernameAttribute,
                        String emailAttribute,
                        String fullnameAttribute,
                        String nameIDFormat,
                        String sslUrl,
                        String loginType,
                        String regexPattern,
                        Boolean enableRegexPattern,
                        Boolean signedRequest,
                        Boolean userCreate,
                        String ssoBindingType,
                        String sloBindingType,
                        Boolean userAttributeUpdate,
                        Boolean disableDefaultLogin,
                        String newUserGroup
    ) {
        super();
        this.idpEntityId = idpEntityId;
        this.ssoUrl = ssoUrl;
        this.publicx509Certificate = publicx509Certificate;
        this.usernameAttribute = usernameAttribute;
        this.emailAttribute = emailAttribute;
        this.nameIDFormat = nameIDFormat;
        this.sslUrl = sslUrl;
        this.loginType = (loginType != null) ? loginType : "usernameLogin";
        this.regexPattern = regexPattern;
        this.enableRegexPattern = (enableRegexPattern != null) ? enableRegexPattern : false;
        this.signedRequest = (signedRequest != null) ? signedRequest : false;
        this.userCreate = (userCreate != null) ? userCreate : false;
        this.ssoBindingType = (ssoBindingType != null) ? ssoBindingType : "HttpRedirect";
        this.sloBindingType = (sloBindingType != null) ? sloBindingType : "HttpRedirect";
        this.userAttributeUpdate = (userAttributeUpdate != null) ? userAttributeUpdate : false;
        this.fullnameAttribute = fullnameAttribute;
        this.disableDefaultLogin = (disableDefaultLogin != null) ? disableDefaultLogin : false;
        this.newUserGroup= newUserGroup;

    }


    @Override
    public String getLoginUrl() {
        if (getDisableDefaultLogin()) {
            return "securityRealm/moSamlLogin";
        }
        return "securityRealm/moLogin";
    }

    @Override
    public void doLogout(StaplerRequest req, StaplerResponse rsp) {
        try {
            LOGGER.fine(" in doLogout");
            super.doLogout(req, rsp);
        } catch (Exception e) {
            LOGGER.fine("error Occurred while generating logout request " + e.getMessage());
        }

    }

    @Override
    public String getPostLogOutUrl(StaplerRequest req, Authentication auth) {

        if (this.disableDefaultLogin) {
            return "/securityRealm/loggedOut";
        }
        return "/securityRealm/moLogin";
    }

    public HttpResponse doMoLogin(final StaplerRequest request, final StaplerResponse response, String errorMessage) {
        String referer= request.getReferer();
        String redirectOnFinish = calculateSafeRedirect(referer);
        request.getSession().setAttribute(REFERER_ATTRIBUTE, redirectOnFinish);
        return (req, rsp, node) -> {
            rsp.setContentType("text/html;charset=UTF-8");
            String html = IOUtils.toString(MoSAMLAddIdp.class.getResourceAsStream(LOGIN_TEMPLATE_PATH), "UTF-8");
            if (StringUtils.isNotBlank(errorMessage)) {
                html = html.replace("<input type=\"hidden\" />", errorMessage);
            }
            rsp.getWriter().println(html);
        };
    }

    @RequirePOST
    public void doMoLoginAction(final StaplerRequest request, final StaplerResponse response) {
        String referer = (String) request.getSession().getAttribute(REFERER_ATTRIBUTE);
        String redirectOnFinish = calculateSafeRedirect(referer);
        recreateSession(request);
        try {
            {
                String username = request.getParameter("j_username");
                username = MoSAMLUtils.sanitizeText(username);
                String password = request.getParameter("j_password");
                password = MoSAMLUtils.sanitizeText(password);
                Boolean isValidUser= Boolean.FALSE ;
                String error = StringUtils.EMPTY;
                if (StringUtils.isNotBlank(username)) {
                    final User user_jenkin = User.getById(username, false);
                    if (user_jenkin != null) {
                        LOGGER.fine("User exist with username = " + username);
                        try {
                            HudsonPrivateSecurityRealm.Details details=user_jenkin.getProperty(HudsonPrivateSecurityRealm.Details.class);
                            isValidUser= details.isPasswordCorrect(password);
                            LOGGER.fine("Valid User Password");
                        } catch (Exception e) {
                            LOGGER.fine("InValid User Password"+e.getMessage());
                            isValidUser = Boolean.FALSE;
                        }
                        if (isValidUser) {
                            HttpSession session = request.getSession(false);
                            if (session != null) {
                                session.invalidate();
                            }
                            request.getSession(true);
                            List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
                            authorities.add(AUTHENTICATED_AUTHORITY);
                            MoSAMLUserInfo userInfo = new MoSAMLUserInfo(username, authorities.toArray(new GrantedAuthority[authorities.size()]));
                            MoSAMLAuthenticationTokenInfo tokenInfo = new MoSAMLAuthenticationTokenInfo(userInfo);
                            SecurityContextHolder.getContext().setAuthentication(tokenInfo);
                            SecurityListener.fireAuthenticated(userInfo);
                            SecurityListener.fireLoggedIn(user_jenkin.getId());
                            response.sendRedirect(redirectOnFinish);
                            return;
                        }
                    }
                    error = "INVALID USER OR PASSWORD";
                }
                String errorMessage = StringUtils.EMPTY;
                if (StringUtils.isNotBlank(error)) {
                    errorMessage = "<div class=\"alert alert-danger\">Invalid username or password</div><br>";
                }
                String html = customLoginTemplate(response, errorMessage);
                response.getWriter().println(html);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String calculateSafeRedirect( String referer) {
        String redirectURL;
        String rootUrl = getBaseUrl();
        {
            if (referer != null && (referer.startsWith(rootUrl) || Util.isSafeToRedirectTo(referer))) {
                redirectURL = referer;
            } else {
                redirectURL = rootUrl;
            }
        }
        LOGGER.fine("Safe URL redirection: " + redirectURL);
        return redirectURL;
    }

    private String customLoginTemplate(StaplerResponse response, String errorMessage) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        String html = IOUtils.toString(MoSAMLAddIdp.class.getResourceAsStream(LOGIN_TEMPLATE_PATH), "UTF-8");

        if (StringUtils.isNotBlank(errorMessage)) {
            LOGGER.fine(errorMessage);

            html = html.replace("<input type=\"hidden\" />", errorMessage);

        }
        return html;
    }

    public void doMoSamlLogin(final StaplerRequest request, final StaplerResponse response, @Header("Referer") final String referer) {
        recreateSession(request);
        String redirectOnFinish = calculateSafeRedirect(referer);
        request.getSession().setAttribute(REFERER_ATTRIBUTE, redirectOnFinish);

        LOGGER.fine("in doMoSamlLogin");
        MoSAMLManager moSAMLManager = new MoSAMLManager(getMoSAMLPluginSettings());
        moSAMLManager.createAuthnRequestAndRedirect(request, response);
    }

    private String getBaseUrl() {
        return get().getRootUrl();
    }

    private String getErrorUrl() {
        return get().getRootUrl() + MO_SAML_JENKINS_LOGIN_ACTION;
    }

    public String spMetadataURL() {
        return get().getRootUrl() + MO_SAML_SP_METADATA_URL;
    }


    @RequirePOST
    public void doMoSAMLSingleSignOnForceStop(final StaplerRequest request, final StaplerResponse response) {
        HttpSession session= request.getSession(false);
        if(session!=null){
            session.invalidate();
        }
        LOGGER.fine("Enable doMoSAMLSingleSignOnForceStop from doPost");
        String username = request.getParameter("username");
        username = MoSAMLUtils.sanitizeText(username);
        String password = request.getParameter("password");
        password = MoSAMLUtils.sanitizeText(password);
        LOGGER.fine("Parameters submitted for backdoor: username: "+username+" Password: "+password);
        if (StringUtils.isBlank(username) && StringUtils.isBlank(password)) {
            sendError(response, HttpServletResponse.SC_UNAUTHORIZED, "Authorization parameters are Missing");
            return;
        }
        final User user_jenkin = User.getById(username, false);
        try {
            if (user_jenkin != null ) {
                HudsonPrivateSecurityRealm.Details details=user_jenkin.getProperty(HudsonPrivateSecurityRealm.Details.class);
                Boolean  isValidUser= details.isPasswordCorrect(password);
                Jenkins j= Jenkins.getInstanceOrNull();
                if (j!=null&& isValidUser)
                    j.setSecurityRealm(new HudsonPrivateSecurityRealm(false));
                JSONObject json = new JSONObject();
                JSONObject success = new JSONObject();
                success.put("Status", "SUCCESS");
                success.put("Message", "Successfully disabled SSO");
                json.put("Message", success);
                response.setContentType(MediaType.APPLICATION_JSON);
                response.setStatus(200);
                response.getOutputStream().write(json.toString().getBytes(StandardCharsets.UTF_8));
                response.getOutputStream().close();
            }
            else{
                LOGGER.fine("User validation failed.");
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED, "UnAuthorize User");
            }
        }
           catch (IOException e)
           {
               LOGGER.fine(e.getMessage());
           }
    }

    private void sendError(StaplerResponse response, int errorCode, String errorMessage) {
        try {
            JSONObject json = new JSONObject();
            JSONObject error = new JSONObject();
            error.put("Status", "ERROR");
            error.put("Message", errorMessage);
            json.put("error", error);
            response.setContentType(MediaType.APPLICATION_JSON);
            response.setStatus(errorCode);
            response.getOutputStream().write(json.toString().getBytes(StandardCharsets.UTF_8));
            response.getOutputStream().close();
        } catch (JSONException | IOException e) {
            LOGGER.fine("An error occurred while sending json response" + e);
        }
    }

    public void doMospmetadata(final StaplerRequest request, final StaplerResponse response) {
        LOGGER.fine("Printing SP Metadata");
        HttpSession session=request.getSession(false);
        if(session!=null){
            MoSAMLPluginSettings moSAMLPluginSettings = getMoSAMLPluginSettings();
            String metadata = getMetadata(moSAMLPluginSettings);
            LOGGER.fine(metadata);
            try {
                response.setHeader("Content-Disposition", "attachment; filename=\"sp_metadata.xml\"");
                response.setHeader("Cache-Control", "max-age=0");
                response.setHeader("Pragma", "");
                response.setContentType(MediaType.APPLICATION_XML);
                response.getOutputStream().write(metadata.getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) {
                LOGGER.fine("An error occurred while downloading the metadata." + e);
            }
        }
    else{
            LOGGER.fine("Invalid Request");
            return;
        }
    }
    public  void doDownloadCertificate(final StaplerRequest request, final StaplerResponse response) throws Exception {
        LOGGER.fine("Downloading SP Certificate.");
        try {
            MoSAMLPluginSettings moSAMLPluginSettings = getMoSAMLPluginSettings();
            String certificate = moSAMLPluginSettings.getPublicSPCertificate();
            response.setHeader("Content-Disposition", "attachment; filename=\"sp-certificate.crt\"");
            response.setHeader("Cache-Control", "max-age=0");
            response.setHeader("Pragma", "");
            response.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            response.getOutputStream().write(certificate.getBytes(StandardCharsets.UTF_8));

        } catch (Exception e) {
            LOGGER.fine("An error occurred while downloading the certificate."+e);
        }

    }

    public String getMetadata(MoSAMLPluginSettings settings) {
        LOGGER.fine("Generating SP Metadata.");
        MoSAMLUtils.doBootstrap();
        EntityDescriptorBuilder builder = new EntityDescriptorBuilder();
        SPSSODescriptorBuilder spssoDescriptorBuilder = new SPSSODescriptorBuilder();
        KeyDescriptorBuilder keyDescriptorBuilder = new KeyDescriptorBuilder();
        KeyInfoBuilder keyInfoBuilder = new KeyInfoBuilder();
        X509DataBuilder x509DataBuilder = new X509DataBuilder();
        X509CertificateBuilder x509CertificateBuilder = new X509CertificateBuilder();
        NameIDFormatBuilder nameIdFormatBuilder = new NameIDFormatBuilder();
        AssertionConsumerServiceBuilder assertionConsumerServiceBuilder = new AssertionConsumerServiceBuilder();
        SingleLogoutServiceBuilder singleLogOutServiceBuilder = new SingleLogoutServiceBuilder();
        OrganizationBuilder organizationBuilder = new OrganizationBuilder();
        OrganizationNameBuilder organizationNameBuilder = new OrganizationNameBuilder();
        OrganizationDisplayNameBuilder organizationDisplayNameBuilder = new OrganizationDisplayNameBuilder();
        OrganizationURLBuilder organizationUrlBuilder = new OrganizationURLBuilder();
        ContactPersonBuilder contactPersonBuilder = new ContactPersonBuilder();
        GivenNameBuilder givenNameBuilder = new GivenNameBuilder();
        EmailAddressBuilder emailAddressBuilder = new EmailAddressBuilder();

        EntityDescriptor entityDescriptor = builder.buildObject();
        SPSSODescriptor spssoDescriptor = spssoDescriptorBuilder.buildObject();
        AssertionConsumerService assertionConsumerService = assertionConsumerServiceBuilder.buildObject();
        Organization organization = organizationBuilder.buildObject();
        ContactPerson contactPersonTechnical = contactPersonBuilder.buildObject();
        ContactPerson contactPersonSupport = contactPersonBuilder.buildObject();

        entityDescriptor.setEntityID(settings.getSPEntityID());

        spssoDescriptor.setWantAssertionsSigned(true);
        spssoDescriptor.addSupportedProtocol("urn:oasis:names:tc:SAML:2.0:protocol");

        //signing
        if (BooleanUtils.toBoolean(settings.getSignedRequest())) {
            spssoDescriptor.setAuthnRequestsSigned(true);
            KeyDescriptor signingKeyDescriptor = keyDescriptorBuilder.buildObject();
            signingKeyDescriptor.setUse(UsageType.SIGNING);
            KeyInfo signingKeyInfo = keyInfoBuilder.buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);
            X509Data signingX509Data = x509DataBuilder.buildObject(X509Data.DEFAULT_ELEMENT_NAME);
            X509Certificate signingX509Certificate = x509CertificateBuilder
                    .buildObject(X509Certificate.DEFAULT_ELEMENT_NAME);
            String certificate = settings.getPublicSPCertificate();
            certificate = MoSAMLUtils.deserializePublicCertificate(certificate);
            signingX509Certificate.setValue(certificate);
            signingX509Data.getX509Certificates().add(signingX509Certificate);
            signingKeyInfo.getX509Datas().add(signingX509Data);
            signingKeyDescriptor.setKeyInfo(signingKeyInfo);
            spssoDescriptor.getKeyDescriptors().add(signingKeyDescriptor);
        }

        SingleLogoutService singleLogoutServiceRedir = singleLogOutServiceBuilder.buildObject();
        singleLogoutServiceRedir
                .setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        singleLogoutServiceRedir.setLocation(settings.getspSLOURL());
        spssoDescriptor.getSingleLogoutServices().add(singleLogoutServiceRedir);

        SingleLogoutService singleLogoutServicePost = singleLogOutServiceBuilder.buildObject();
        singleLogoutServicePost.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        singleLogoutServicePost.setLocation(settings.getspSLOURL());
        spssoDescriptor.getSingleLogoutServices().add(singleLogoutServicePost);

        List<String> nameIds = new ArrayList<>();
        nameIds.add("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
        nameIds.add("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        nameIds.add("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        nameIds.add("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");

        for (String nameId : nameIds) {
            NameIDFormat nameIDFormat = nameIdFormatBuilder.buildObject();
            nameIDFormat.setFormat(nameId);
            spssoDescriptor.getNameIDFormats().add(nameIDFormat);
        }

        assertionConsumerService.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        assertionConsumerService.setLocation(settings.getSpAcsUrl());
        assertionConsumerService.setIndex(1);
        spssoDescriptor.getAssertionConsumerServices().add(assertionConsumerService);

        entityDescriptor.getRoleDescriptors().add(spssoDescriptor);

        OrganizationName organizationName = organizationNameBuilder.buildObject();
        organizationName.setName(new LocalizedString(settings.getOrganizationName(), Locale.getDefault().getLanguage()));
        organization.getOrganizationNames().add(organizationName);
        OrganizationDisplayName organizationDisplayName = organizationDisplayNameBuilder.buildObject();
        organizationDisplayName.setName(new LocalizedString(settings.getOrganizationDisplayName(), Locale.getDefault().getLanguage()));
        organization.getDisplayNames().add(organizationDisplayName);
        OrganizationURL organizationURL = organizationUrlBuilder.buildObject();
        organizationURL.setURL(new LocalizedString(settings.getOrganizationUrl(), Locale.getDefault().getLanguage()));
        organization.getURLs().add(organizationURL);
        entityDescriptor.setOrganization(organization);

        contactPersonTechnical.setType(ContactPersonTypeEnumeration.TECHNICAL);
        GivenName givenNameTechnical = givenNameBuilder.buildObject();
        givenNameTechnical.setName(settings.getTechnicalContactName());
        contactPersonTechnical.setGivenName(givenNameTechnical);
        EmailAddress emailAddressTechnical = emailAddressBuilder.buildObject();
        emailAddressTechnical.setAddress(settings.getTechnicalContactEmail());
        contactPersonTechnical.getEmailAddresses().add(emailAddressTechnical);

        contactPersonSupport.setType(ContactPersonTypeEnumeration.SUPPORT);
        GivenName givenNameSupport = givenNameBuilder.buildObject();
        givenNameSupport.setName(settings.getSupportContactName());
        contactPersonSupport.setGivenName(givenNameSupport);
        EmailAddress emailAddressSupport = emailAddressBuilder.buildObject();
        emailAddressSupport.setAddress(settings.getSupportContactEmail());
        contactPersonSupport.getEmailAddresses().add(emailAddressSupport);

        entityDescriptor.getContactPersons().add(contactPersonTechnical);
        entityDescriptor.getContactPersons().add(contactPersonSupport);

        try {
            MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(entityDescriptor);
            Element element = marshaller.marshall(entityDescriptor);
            return XMLHelper.nodeToString(element);
        } catch (Exception e) {
            LOGGER.fine("Marshalling Exception:" + e);
        }
        return null;
    }

    @RequirePOST
    public HttpResponse doMoSamlAuth(final StaplerRequest request, final StaplerResponse response) throws IOException {
        String redirectUrl = getBaseUrl();
        recreateSession(request);
        LOGGER.fine(" Reading SAML Response");
        String username = "";
        String email = "";
        MoSAMLPluginSettings settings = getMoSAMLPluginSettings();
        MoSAMLResponse MoSAMLResponse ;
        MoSAMLManager moSAMLManager = new MoSAMLManager(getMoSAMLPluginSettings());

        try {
            MoSAMLResponse = moSAMLManager.readSAMLResponse(request, response);

            if (MoSAMLResponse.getAttributes().get(settings.getUsernameAttribute()) != null
                    && MoSAMLResponse.getAttributes().get(settings.getUsernameAttribute()).length == 1) {
                username = MoSAMLResponse.getAttributes().get(settings.getUsernameAttribute())[0];
            }

            if (MoSAMLResponse.getAttributes().get(settings.getEmailAttribute()) != null
                    && MoSAMLResponse.getAttributes().get(settings.getEmailAttribute()).length == 1) {
                email = MoSAMLResponse.getAttributes().get(settings.getEmailAttribute())[0];
            }

            LOGGER.fine("Username received: " + username + " email received = " + email);
            LOGGER.fine("Login Method for Users is:" + settings.getLoginType());
            if (settings.getLoginType().equals("usernameLogin") && StringUtils.isNotBlank(username)) {
                LOGGER.fine("User name Login Selected");
                username=handleUsernameLogin(username, settings);
                User user = User.getById(username, false);

                if (user == null && !settings.getUserCreate()) {
                    LOGGER.fine("User does not exist");
                    String errorMessage = "<div class=\"alert alert-danger\">User does not Exist</div><br>";
                    return doMoLogin(request, response, errorMessage);
                } else if (user == null && settings.getUserCreate()) {
                    username=handleUsernameLogin(username, settings);
                    User newUser = userCreateSAML( username, email, settings, MoSAMLResponse);
                    if (newUser == null) {
                        LOGGER.fine("User creation Failed");
                        String errorMessage = "<div class=\"alert alert-danger\">User creation Failed. Please view logs for more information.<br>";
                        return doMoLogin(request, response, errorMessage);
                    } else {
                        return createSessionAndLoginUser(newUser,request,response, true,settings, redirectUrl);
                    }
                } else {
                    return createSessionAndLoginUser(user,request,response,false,settings,redirectUrl);
                }

            } else if(settings.getLoginType().equals("emailLogin") && StringUtils.isNotBlank(email)){
                LOGGER.fine("Email Login Selected");
                ArrayList<String> usernameList = handleEmailLogin(request, response, email, settings, MoSAMLResponse);
                if(usernameList.size() != 1){
                    LOGGER.fine("Multiple Mail Addresses");
                    String errorMessage = "<div class=\"alert alert-danger\">More than one user found with this email address.</div><br>";
                    return doMoLogin(request,response,errorMessage);}
                User user= User.getById(usernameList.get(0),false);
                if (user == null && !settings.getUserCreate()) {
                    LOGGER.fine("User does not exist");
                    String errorMessage = "<div class=\"alert alert-danger\">User does not Exist</div><br>";
                    return doMoLogin(request, response, errorMessage);
                } else if (user == null && settings.getUserCreate()) {
                    User newUser = userCreateSAML(username, email, settings, MoSAMLResponse);
                    if (newUser == null) {
                        LOGGER.fine("User creation Failed");
                        String errorMessage = "<div class=\"alert alert-danger\">User creation Failed.<br>";
                        return doMoLogin(request, response, errorMessage);
                    } else {
                        return createSessionAndLoginUser(newUser,request,response,true,settings,redirectUrl);
                    }
                } else {
                   return createSessionAndLoginUser(user,request,response,false,settings,redirectUrl);

                }

            }
            else {
                LOGGER.fine("Invalid login Attribute");
                String errorMessage = "<div class=\"alert alert-danger\">Username not received in the SAML Response. Please check your configuration.</div><br>";
                return doMoLogin(request, response, errorMessage);
            }

        } catch (Exception ex) {
            LOGGER.fine("Invalid response");
            String errorMessage = "<div class=\"alert alert-danger\">Error occurred while reading response.</div><br>";
            return doMoLogin(request, response, errorMessage);

        }

    }

    private ArrayList<String> handleEmailLogin(StaplerRequest request, StaplerResponse response, String email, MoSAMLPluginSettings settings, MoSAMLResponse moSAMLResponse) {
        ArrayList<String> usernameList= new ArrayList<String>();
        try {
            Collection<User> users = User.getAll();

            for (User user : users) {
                String emailAddress = user.getProperty(Mailer.UserProperty.class).getAddress();
                if (emailAddress.equals(email)) {
                    usernameList.add(user.getId());
                }
            }

        } catch (Exception e) {
            LOGGER.fine("Error Occurred while searching for user");
            return usernameList;
        }
        return usernameList;
    }

    private User userCreateSAML( String username, String email, MoSAMLPluginSettings settings, MoSAMLResponse moSAMLResponse) {
            User new_user=null;
        try {
                new_user = User.getById(username, true);

                if(new_user!=null ){
                    new_user.addProperty(new Mailer.UserProperty(email));
                }

        } catch (IOException e) {
            e.printStackTrace();
            return new_user;
        }
        return new_user;
    }


    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(authentication -> {
            if (authentication instanceof MoSAMLAuthenticationTokenInfo) {
                return authentication;
            }
            throw new BadCredentialsException("Invalid Auth type " + authentication);
        });
    }

    private String handleUsernameLogin(String username, MoSAMLPluginSettings settings) {
        String regexPattern = "";
        if (StringUtils.isNotBlank(settings.getRegexPattern()) && settings.getEnableRegexPattern()) {
            LOGGER.fine("Regex Login for Username");
            regexPattern = settings.getRegexPattern();
            try {
                Pattern pattern = Pattern.compile(StringUtils.trimToEmpty(regexPattern));
                Matcher matcher = pattern.matcher(username);
                LOGGER.fine(String.valueOf(matcher));
                if (matcher.find()) {
                    username = org.apache.commons.lang3.StringUtils.EMPTY;
                    if (matcher.groupCount() > 0) {
                        for (int i = 1; i <= matcher.groupCount(); i++) {
                            username += matcher.group(i);
                        }
                    } else {
                        username = matcher.group();
                    }
                }
            } catch (Exception e) {
                LOGGER.fine("Can't sign in regex pattern exception occured" + e);
                return username;
            }
        }
       return username;

    }
    public  HttpResponse createSessionAndLoginUser(User user, StaplerRequest request,StaplerResponse response, Boolean newUserCreated,MoSAMLPluginSettings settings, String redirectUrl){
        if (user != null) {
            LOGGER.fine("User exists for Username: " + user.getId());

            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }
            session = request.getSession(true);

            session.setAttribute("sessionIndex", MoSAMLUtils.generateRandomAlphaNumericKey(16));
            session.setAttribute("nameID", user.getId());

            UserDetails details = user.getUserDetailsForImpersonation();
            LOGGER.fine("UserDetails"+details);

            GrantedAuthority[] authorities= details.getAuthorities();
            List<GrantedAuthority>authorityList= new ArrayList<>();
            for (GrantedAuthority authority : authorities) {

                authorityList.add(authority);
            }
            MoSAMLUserInfo userInfo = new MoSAMLUserInfo(user.getId(), authorityList.toArray(new GrantedAuthority[authorityList.size()]));
            MoSAMLAuthenticationTokenInfo tokenInfo = new MoSAMLAuthenticationTokenInfo(userInfo);
            SecurityContextHolder.getContext().setAuthentication(tokenInfo);
            SecurityListener.fireAuthenticated(userInfo);
            SecurityListener.fireLoggedIn(user.getId());
           return HttpResponses.redirectTo(redirectUrl);

        } else {
            LOGGER.fine("User does not exist.");
            String errorMessage = "<div class=\"alert alert-danger\">User does not exist..</div><br>";
            return doMoLogin(request,response,errorMessage);
        }
    }

    public String getIdpEntityId() {
        return idpEntityId;
    }

    public String getSsoUrl() {
        return ssoUrl;
    }

    public String getPublicx509Certificate() {
        return publicx509Certificate;
    }

    public String getUsernameAttribute() {
        if (StringUtils.isEmpty(usernameAttribute)) {
            return "NameID";
        } else {
            return usernameAttribute;
        }
    }

    public String getEmailAttribute() {
        if (StringUtils.isEmpty(emailAttribute)) {
            return "NameID";
        } else {
            return emailAttribute;
        }
    }
    /**
     * check if a request contains a session, if so, it invalidate the session and create new one to avoid session
     * fixation.
     * @param request request.
     */
    private void recreateSession(StaplerRequest request) {
        HttpSession session = request.getSession(false);
        if(session != null){
            LOGGER.fine("Invalidate previous session");
            // avoid session fixation
            session.invalidate();
        }
        request.getSession(true);
    }



    public Boolean getDisableDefaultLogin() {
        return disableDefaultLogin;
    }

    public String getNameIDFormat() {
        return nameIDFormat;
    }

    public Boolean getSignedRequest() {
        return BooleanUtils.toBooleanDefaultIfNull(signedRequest, true);
    }

    public Boolean getUserCreate() {
        return userCreate;
    }

    public String getSslUrl() {
        return sslUrl;
    }

    public String getLoginType() {
        return loginType;
    }

    public String getRegexPattern() {
        return regexPattern;
    }

    public Boolean getEnableRegexPattern() {
        return enableRegexPattern;
    }

    public String getSsoBindingType() {
        return ssoBindingType;
    }

    public String getSloBindingType() {
        return sloBindingType;
    }


    public String getsPEntityID() {
        String rootURL= Jenkins.getInstance().getRootUrl();
        if(rootURL.endsWith("/")){
            rootURL= rootURL.substring(0,rootURL.length()-1);
        }
        return rootURL;
    }

    public String getAudienceURI() {
        String rootURL= Jenkins.getInstance().getRootUrl();
        if(rootURL.endsWith("/")){
            rootURL= rootURL.substring(0,rootURL.length()-1);
        }
        return rootURL;
    }

    public String getAcsURL() {
        String rootURL= Jenkins.getInstance().getRootUrl();
        if(rootURL.endsWith("/")){
            rootURL= rootURL.substring(0,rootURL.length()-1);
        }
        return rootURL+"/securityRealm/moSamlAuth";
    }

    public String getSpLogoutURL() {
        String rootURL= Jenkins.getInstance().getRootUrl();
        if(rootURL.endsWith("/")){
            rootURL= rootURL.substring(0,rootURL.length()-1);
        }
        return rootURL+"/securityRealm/logout";
    }
    public String getBackdoorURL() {
        String rootURL= Jenkins.getInstance().getRootUrl();
        if(rootURL.endsWith("/")){
            rootURL= rootURL.substring(0,rootURL.length()-1);
        }
        return rootURL+"/securityRealm/moLoginAction";
    }

    public String getFullnameAttribute() {
        return fullnameAttribute;
    }

    public Boolean getUserAttributeUpdate() {
        return userAttributeUpdate;
    }








    private MoSAMLPluginSettings getMoSAMLPluginSettings() {
        MoSAMLPluginSettings settings = new MoSAMLPluginSettings(idpEntityId, ssoUrl, publicx509Certificate,
                usernameAttribute, emailAttribute, nameIDFormat,
                sslUrl, loginType, regexPattern,
                enableRegexPattern, signedRequest, userCreate,
                ssoBindingType, sloBindingType, fullnameAttribute, userAttributeUpdate,
                newUserGroup);
        return settings;
    }

    private MoSAMLManager getMoSAMLManager() {
        MoSAMLManager moSAMLManager = new MoSAMLManager(getMoSAMLPluginSettings());
        return moSAMLManager;
    }



    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

        public DescriptorImpl() {
            super();
        }

        public DescriptorImpl(Class<? extends SecurityRealm> clazz) {
            super(clazz);
        }

        @Override
        public String getDisplayName() {
            return "miniOrange SAML 2.0";
        }


        public FormValidation doCheckIdpEntityId(@QueryParameter String idpEntityId) {
            if (StringUtils.isEmpty(idpEntityId)) {
                return FormValidation.error("The Entity ID URL Can not be kept blank.");
            }
            try {
                new URL(idpEntityId);
            } catch (MalformedURLException e) {
                return FormValidation.error("The URL is malformed.", e);
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckSsoUrl(@QueryParameter String ssoUrl) {
            if (StringUtils.isEmpty(ssoUrl)) {
                return FormValidation.error("The Single Sign On URL Can not be kept blank.");
            }
            try {
                new URL(ssoUrl);
            } catch (MalformedURLException e) {
                return FormValidation.error("The URL is malformed.", e);
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckUsernameAttribute(@QueryParameter String usernameAttribute, @QueryParameter String loginType) {
            if (StringUtils.isEmpty(usernameAttribute) && loginType.equals("usernameLogin")) {
                return FormValidation.warning("Username Can not kept blank");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckEmailAttribute(@QueryParameter String emailAttribute, @QueryParameter String loginType) {
            if (StringUtils.isEmpty(emailAttribute) && loginType.equals("emailLogin")) {
                return FormValidation.warning("Email Address Can not kept blank");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckX509Certificate(@QueryParameter String publicx509Certificate) {
            if (StringUtils.isEmpty(publicx509Certificate)) {
                return FormValidation.error("Certificate cannot be kept blank.");
            }
            else if(StringUtils.isNotBlank(publicx509Certificate))
            {
                Boolean validCertificate= MoSAMLUtils.isValidPublicCertificate(publicx509Certificate);
                LOGGER.fine("is certificate valid:"+validCertificate);
                if(validCertificate){
                    return FormValidation.ok();
                }
                else
                    return FormValidation.error("Invalid Certificate");
            }
            return FormValidation.error("Certificate validation failed.");
        }


        public FormValidation doCheckRegexPattern(@QueryParameter Boolean enableRegexPattern, @QueryParameter String regexPattern) {

            if (enableRegexPattern && StringUtils.isEmpty(regexPattern)) {
                return FormValidation.error("The Regex Pattern is not Valid");
            } else {
                return FormValidation.ok();
            }
        }

        public FormValidation doUserCreate(@QueryParameter Boolean userCreate, @QueryParameter String emailAttribute, @QueryParameter String usernameAttribute) {

            if (userCreate && StringUtils.isEmpty(emailAttribute) && StringUtils.isEmpty(usernameAttribute)) {
                return FormValidation.error("Email and Username Attributes are required.");
            } else {
                return FormValidation.ok();
            }
        }


        public String getsPEntityID() {
            String rootURL= Jenkins.getInstance().getRootUrl();
            if(rootURL.endsWith("/")){
                rootURL= rootURL.substring(0,rootURL.length()-1);
            }
            return rootURL;
        }

        public String getAudienceURI() {
            String rootURL= Jenkins.getInstance().getRootUrl();
            if(rootURL.endsWith("/")){
                rootURL= rootURL.substring(0,rootURL.length()-1);
            }
            return rootURL;
        }

        public String getAcsURL() {
            String rootURL= Jenkins.getInstance().getRootUrl();
            if(rootURL.endsWith("/")){
                rootURL= rootURL.substring(0,rootURL.length()-1);
            }
            return rootURL+"/securityRealm/moSamlAuth";
        }

        public String getSpLogoutURL() {
            String rootURL= Jenkins.getInstance().getRootUrl();
            if(rootURL.endsWith("/")){
                rootURL= rootURL.substring(0,rootURL.length()-1);
            }
            return rootURL+"/securityRealm/logout";
        }

     }


}
