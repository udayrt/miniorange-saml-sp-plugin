package org.miniorange.saml;


import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Describable;
import hudson.model.Descriptor;
import hudson.model.ManagementLink;
import hudson.security.SecurityRealm;
import hudson.util.FormApply;
import jenkins.model.Jenkins;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.interceptor.RequirePOST;

import javax.annotation.CheckForNull;
import java.util.logging.Logger;

import static jenkins.model.Jenkins.get;

@Extension
public class MoPluginConfigView extends ManagementLink implements Describable<MoPluginConfigView> {


    private static final Logger LOGGER = Logger.getLogger(MoPluginConfigView.class.getName());

    @RequirePOST
    @Restricted(NoExternalUse.class)
    public void doSaveConfiguration(StaplerRequest request, StaplerResponse response) throws Exception {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        MoSAMLAddIdp.DESCRIPTOR.doRealmSubmit(request, response);
        FormApply.success(request.getContextPath() + "/").generateResponse(request, response, null);
    }

    public @NonNull String getCategoryName() {
        return "SECURITY";
    }


    @edu.umd.cs.findbugs.annotations.CheckForNull
    public SecurityRealm getRealm() {
        SecurityRealm realm = Jenkins.get().getSecurityRealm();
        if (realm instanceof MoSAMLAddIdp) {
            return realm;
        } else {
            return null;
        }
    }


    @CheckForNull
    @Override
    public String getIconFileName() {
        String icon = null;
        if (Jenkins.get().getSecurityRealm() instanceof MoSAMLAddIdp) {
            icon = "symbol-id-card";
        }
        return icon;
    }

    @CheckForNull
    @Override
    public String getDisplayName() {
        return "miniOrange SAML SSO";
    }


    @CheckForNull
    @Override
    public String getUrlName() {
        return "MoPluginConfigView";
    }

    @Override
    public String getDescription() {
        return "Secure Single Sign-On (SSO) solution that allows user to login to their apps using   IDP credentials by SAML Authentication.";
    }

    public String getBaseUrl() {
        String rootURL = get().getRootUrl();
        if (rootURL.endsWith("/")) {
            rootURL = rootURL.substring(0, rootURL.length() - 1);
        }
        return rootURL;
    }

    @SuppressWarnings("unchecked")
    @Override
    public Descriptor<MoPluginConfigView> getDescriptor() {
        Jenkins jenkins = Jenkins.getInstance();

        if (jenkins == null) {
            throw new IllegalStateException("Jenkins has not been started");
        }
        return jenkins.getDescriptorOrDie(getClass());
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<MoPluginConfigView> {
        public DescriptorImpl() {}
    }




}



