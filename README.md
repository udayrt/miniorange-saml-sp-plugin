# Miniorange SAML Plugin for Jenkins
miniOrange SAML Single Sign On (SSO) plugin acts as a SAML Service Provider which can be configured to establish trust between the plugin and SAML capable Identity Providers to securely authenticate the user to the Jenkins.

Features of Jenkins Saml SP Plugin

* Simple and easy-to-use [ FREE ]
* Supports both SSO and Jenkins’ own login at the same time [FREE]
* Auto-redirect to IdP[ PREMIUM ]
* Back-door Login [ PREMIUM ]
* Single Logout [ PREMIUM ]

Supported IDP’s:

We support all known IdPs - 
ADFS, Azure AD, Bitium, Centrify, Google Apps, IBM, NetIQ, Okta, OneLogin,  OpenAM, Oracle,  Ping,  RSA,  Salesforce, Shibboleth, SimpleSAMLphp, WSO2, etc.
In addition to the above, [miniOrange](/docs/images/miniorange_as_idp.md) also provides On-Premise IDP. 

[Okta SetupGuidelines](/docs/images/okta_as_idp.md)

 SAML Single Sign-on (SSO) acts as a SAML 2.0 Service Provider and securely authenticate users with your SAML 2.0 Identity Provider.

## On Jenkins side:

**Step 1: Download and install the plugin in Jenkins.**

To download the miniorange saml SP plugin follow the path:
**Through Jenkins plugin directory**
* Login to your Jenkins.
* Go to Manage Jenkins option from the left pane, and open Manage Plugins tab.

![image_1](docs/images/configuration/manage_plugin_1.png)

* Search for ‘Miniorange saml’ in the available tab.
* Download and install with a restart.

![image_2](docs/images/configuration/plugin_installed_2.png)

Or
**Manual Configuration:**
* Login to your Jenkins.
* Go to Manage Jenkins option from the left pane, and open Manage Plugins tab.
* Go to the advanced tab and upload the hpi file.

![image_3](docs/images/configuration/upload_plugin_3.png)

![image_4](docs/images/configuration/plugin_installed_2.png)

**Step 2: To activate the plugin**

* Open Manage Jenkins => Configure Global Security and set the Security Realm as miniorange SAML 2.0.

![image_5](docs/images/configuration/configure_global_sec_5.png)

            Make sure that Enable Security checkbox is checked.
            
![image_6](docs/images/configuration/config_global_sec_6.PNG)

**Step:3: Fill the required details of IDP and press apply and save the settings.**
* Fill the required details of IDP and press apply and save the settings.

![image_6](docs/images/configuration/config_jenkins_7.png)

