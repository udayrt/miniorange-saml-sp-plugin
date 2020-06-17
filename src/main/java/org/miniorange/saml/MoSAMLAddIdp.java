package org.miniorange.saml;
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
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.*;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.apache.commons.io.IOUtils;
import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;


import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import java.util.logging.Logger;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.BadCredentialsException;
import hudson.tasks.Mailer;

public class MoSAMLAddIdp extends SecurityRealm{

    private static final Logger LOGGER = Logger.getLogger(MoSAMLAddIdp.class.getName());
    public static final String MO_SAML_SP_AUTH_URL = "securityRealm/moSamlAuth";
    public static final String MO_SAML_JENKINS_LOGIN_ACTION = "securityRealm/moLoginAction";
    public static final String MO_SAML_SSO_FORCE_STOP = "securityRealm/moSAMLSingleSignOnForceStop";


    private static final String LOGIN_TEMPLATE_PATH = "/templates/mosaml_login_page_template.html";

    private String idpEntityId;
    private String ssoUrl;

    private String x509Certificate;
    // Information related to Attribute Mapping
    private String usernameAttribute;
    private String emailAttribute;
    private String nameIDFormat;

    @DataBoundConstructor
    public MoSAMLAddIdp(String idpEntityId,
                        String ssoUrl,
                        String x509Certificate,
                        String usernameAttribute,
                        String emailAttribute,
                        String nameIDFormat
    ) {
        super();
        this.idpEntityId = idpEntityId;
        this.ssoUrl = ssoUrl;
        this.x509Certificate = x509Certificate;
        this.usernameAttribute = "NameID";
        this.emailAttribute = "NameID";
        this.nameIDFormat= nameIDFormat;
        if (StringUtils.isNotEmpty(usernameAttribute)) {
            this.usernameAttribute = usernameAttribute;
        }

        if (StringUtils.isNotEmpty(emailAttribute)) {
            this.emailAttribute = emailAttribute;
        }

    }
    @Override
    public String getLoginUrl() {
        return "securityRealm/moLoginAction";
    }
    @Override
    public void doLogout(StaplerRequest req, StaplerResponse rsp) {
        try {

            super.doLogout(req, rsp);
        } catch (ServletException e) {
            LOGGER.fine("Throwing Servlet Exception during logout");
        } catch (IOException e) {
            LOGGER.fine("Throwing IOException during logout");
        }
    }

    @Override
    public String getPostLogOutUrl(StaplerRequest req, Authentication auth) {
        return "securityRealm/moLoginAction";
    }

    public HttpResponse doMoLogin(final StaplerRequest request, final StaplerResponse response,String errorMessage)
    {
        return new HttpResponse() {
            public void generateResponse(StaplerRequest req, StaplerResponse rsp, Object node) throws IOException, ServletException {
                rsp.setContentType("text/html;charset=UTF-8");
                String html = IOUtils.toString(MoSAMLAddIdp.class.getResourceAsStream(LOGIN_TEMPLATE_PATH), "UTF-8");
                if(StringUtils.isNotBlank(errorMessage))
                {
                    html = html.replace("<input type=\"hidden\" />", errorMessage);
                }
                rsp.getWriter().println(html);
            }
        };
    }


    public  void doMoLoginAction(final StaplerRequest request, final StaplerResponse response) {
        try {
            String username = request.getParameter("j_username");
            String password = request.getParameter("j_password");
            Boolean isValidUser = Boolean.FALSE;
            String error = StringUtils.EMPTY;
            if (StringUtils.isNotBlank(username)) {
                final User user_jenkin = User.getById(username,false);
                if (user_jenkin != null) {
                    LOGGER.fine("User exist with username = " + username);
                    try {
                        new MoHudsonPrivateSecurityRealm().authenticate(username, password);
                        LOGGER.fine("Valid User Password");
                        isValidUser = Boolean.TRUE;
                    } catch (Exception e) {
                        LOGGER.fine("InValid User Password");
                        isValidUser = Boolean.FALSE;
                    }
                    if(isValidUser)
                    {
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
                        response.sendRedirect(getBaseUrl());
                        return;
                    }
                }
                error = "INVALID USER OR PASSWORD";
            }
            String errorMessage = StringUtils.EMPTY;
            if (StringUtils.isNotBlank(error)) {
                errorMessage = "<div class=\"alert alert-danger\">Invalid username or password</div><br>";
            }
            String html = customLoginTemplate(response,errorMessage);
            response.getWriter().println(html);
        } catch (Exception e) {
            e.printStackTrace();
        }
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
    public  void doMoSamlLogin(final StaplerRequest request, final StaplerResponse response) {
      LOGGER.fine("in doMoSamlLogin");
        MoSAMLManager moSAMLManager= new MoSAMLManager(getMoSAMLPluginSettings());
        moSAMLManager.createAuthnRequestAndRedirect(request, response);
    }

    private String getBaseUrl() {
        return Jenkins.get().getRootUrl();
    }
    private String getErrorUrl() {
        return Jenkins.get().getRootUrl()+MO_SAML_JENKINS_LOGIN_ACTION;
    }


    public HttpResponse doMoSAMLSingleSignOnForceStop(final StaplerRequest request, final StaplerResponse response) {
        Jenkins.getInstanceOrNull().setSecurityRealm(new HudsonPrivateSecurityRealm(false));
        return HttpResponses.redirectTo(getBaseUrl());
    }

    @RequirePOST
    public HttpResponse doMoSamlAuth (final StaplerRequest request, final StaplerResponse response) throws IOException {
        LOGGER.fine(" Reading SAML Response");
        String samlResponse = request.getParameter("SAMLResponse");
        MoSAMLPluginSettings settings = getMoSAMLPluginSettings();
        String xmlData = new String(Base64.getDecoder().decode(samlResponse));
        MoSAMLResponse MoSAMLResponse = null;
        MoSAMLManager moSAMLManager= new MoSAMLManager(getMoSAMLPluginSettings());

        try {
            MoSAMLResponse = moSAMLManager.readSAMLResponse(request, response);
            String username = "";
            String email = "";
            if (MoSAMLResponse.getAttributes().get(settings.getUsernameAttribute()) != null
                    && MoSAMLResponse.getAttributes().get(settings.getUsernameAttribute()).length == 1) {
                username = MoSAMLResponse.getAttributes().get(settings.getUsernameAttribute())[0];
            }

            if (MoSAMLResponse.getAttributes().get(settings.getEmailAttribute()) != null
                    && MoSAMLResponse.getAttributes().get(settings.getEmailAttribute()).length == 1) {
                email = MoSAMLResponse.getAttributes().get(settings.getEmailAttribute())[0];
            }

            LOGGER.fine("Username received: " + username + "email received = " + email);
            if (StringUtils.isNotBlank(username)) {
                User user = User.getById(username, false);
                LOGGER.fine("User exists for Username: "+username);
                if (user != null) {
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
                    SecurityListener.fireLoggedIn(user.getId());
                    return HttpResponses.redirectTo(getBaseUrl());
                }
            } else {
                LOGGER.fine("User does not exist.");
                String errorMessage = "<div class=\"alert alert-danger\">User does not exist..</div><br>";
                return doMoLogin(request, response,errorMessage);
            }
        } catch (Exception ex) {

            LOGGER.fine("Invalid response");
            String errorMessage = "<div class=\"alert alert-danger\">Error occurred while reading response.</div><br>";
            return doMoLogin(request, response,errorMessage);

        }
        LOGGER.fine("Error occurred .Please contact your administrator,");
        String errorMessage = "<div class=\"alert alert-danger\">Error occurred .Please contact your administrator.</div><br>";
        return doMoLogin(request, response,errorMessage);
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(new AuthenticationManager() {

            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                if (authentication instanceof MoSAMLAuthenticationTokenInfo) {
                    return authentication;
                }
                throw new BadCredentialsException("Invalid Auth type " + authentication);
            }

        });
    }

    public String getIdpEntityId() {
        return idpEntityId;
    }

    public String getSsoUrl() {
        return ssoUrl;
    }

    public String getX509Certificate() {
        return x509Certificate;
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

    public String getNameIDFormat() {
        if (StringUtils.isEmpty(nameIDFormat)) {
            return "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
        } else {
            return emailAttribute;
        }
    }

    private MoSAMLPluginSettings getMoSAMLPluginSettings()  {
        MoSAMLPluginSettings settings = new MoSAMLPluginSettings(idpEntityId, ssoUrl, x509Certificate, usernameAttribute, emailAttribute,0,nameIDFormat);
        return  settings;
    }
    private MoSAMLManager getMoSAMLManager(){
        MoSAMLManager moSAMLManager= new MoSAMLManager(getMoSAMLPluginSettings());
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
                return FormValidation.ok();
            }
            try {
                new URL(idpEntityId);
            } catch (MalformedURLException e) {
                return FormValidation.error("The url is malformed.", e);
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckSsoUrl(@QueryParameter String ssoUrl) {
            if (StringUtils.isEmpty(ssoUrl)) {
                return FormValidation.ok();
            }
            try {
                new URL(ssoUrl);
            } catch (MalformedURLException e) {
                return FormValidation.error("The url is malformed.", e);
            }
            return FormValidation.ok();
        }


        public FormValidation doCheckX509Certificate(@QueryParameter String x509Certificate) {
            if (StringUtils.isEmpty(x509Certificate)&&!MoSAMLUtils.isValidPublicCertificate(x509Certificate)) {
                return FormValidation.error("Invalid Certificate");
            }
            return FormValidation.ok();
        }


    }
}
