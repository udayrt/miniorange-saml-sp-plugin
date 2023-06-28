package org.miniorange.saml;


import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Describable;
import hudson.model.Descriptor;
import hudson.model.ManagementLink;
import hudson.security.SecurityRealm;
import hudson.util.FormApply;
import jenkins.model.Jenkins;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.FileWriterWithEncoding;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.interceptor.RequirePOST;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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


    @NonNull
    @Override
    public String getIconFileName() {
        String icon = null;
        if (Jenkins.get().getSecurityRealm() instanceof MoSAMLAddIdp) {
            icon = "symbol-id-card";
        }
        return icon;
    }

    @NonNull
    @Override
    public String getDisplayName() {
        return "miniOrange SAML SSO";
    }


    @NonNull
    @Override
    public String getUrlName() {
        return "MoPluginConfigView";
    }

    @Override
    public String getDescription() {
        return "Secure Single Sign-On (SSO) solution that allows user to login to their apps using   IDP credentials by SAML Authentication.";
    }

    @SuppressWarnings("unused")
    public void doDownload(StaplerRequest req, StaplerResponse rsp) throws IOException {

        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        rsp.setContentType("application/octet-stream");
        rsp.setHeader("Content-Disposition", "attachment; filename=MoSamlConfiguration.json");

        SecurityRealm realm = get().getSecurityRealm();
        if( realm instanceof MoSAMLAddIdp){

            String content = realm.toString();
            File MoSamlConfiguration = new File("MoSamlConfiguration.json");

            try (OutputStreamWriter writer = new OutputStreamWriter(Files.newOutputStream(MoSamlConfiguration.toPath()), StandardCharsets.UTF_8)) {
                try (PrintWriter printWriter = new PrintWriter(writer)) {
                    printWriter.println(content);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

            try (FileInputStream in = new FileInputStream(MoSamlConfiguration)) {
                IOUtils.copy(in, rsp.getOutputStream());
            } finally {
                if (MoSamlConfiguration.exists()) {
                    MoSamlConfiguration.delete();
                }
            }
        }
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
        Jenkins jenkins = Jenkins.get();

        if (jenkins == null) {
            throw new IllegalStateException("Jenkins has not been started");
        }
        return jenkins.getDescriptorOrDie(getClass());
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<MoPluginConfigView> {
        public DescriptorImpl() {
        }
    }


}



