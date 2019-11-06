# Miniorange SAML SP Plugin
miniOrange SAML Single Sign On (SSO) plugin acts as a SAML Service Provider which can be configured to establish trust between the plugin and SAML capable Identity Providers to securely authenticate the user to the Jenkins.

Features of Jenkins Saml SP Plugin

* Simple and easy-to-use [ FREE ]
* Supports both SSO and Jenkins’ own login at the same time [FREE]
* Auto-create[only 10]/ Auto-login users in OctoberCMS [ FREE ]
* Auto-redirect to IdP[ PREMIUM ]
* Back-door Login [ PREMIUM ]
* Single Logout [ PREMIUM ]

Supported IDP’s:

We support all known IdPs - 
ADFS, Azure AD, Bitium, Centrify, Google Apps, IBM, NetIQ, Okta, OneLogin,  OpenAM, Oracle,  Ping,  RSA,  Salesforce, Shibboleth, SimpleSAMLphp, WSO2, etc.
In addition to the above, miniOrange also provides On-Premise IDP. 

 SAML Single Sign-on (SSO) acts as a SAML 2.0 Service Provider and securely authenticate users with your SAML 2.0 Identity Provider.

## On Jenkins side:

**Step 1: Download and install the plugin in Jenkins.**

To download the miniorange saml SP plugin follow the path:
* Login to your Jenkins.
* Go to Manage Jenkins option from the left pane, and open Manage Plugins tab.
* Search for ‘Miniorange saml’ in the available tab.
* Download and install with a restart.

**Step 2: To activate the plugin**

* Open Manage Jenkins => Configure Global Security and set the Security Realm as miniorange SAML 2.0.
            Make sure that Enable Security checkbox is checked.

// image ![Image description](link-to-image)
**Step 3: Setting up the IDP data**

* Fill the required details of IDP and press apply and save the settings.
//image
## On IDP side:
**Okta as an IDP**

**Step 1: Create a new Application**
* Log into Okta Admin Console.
* Navigate to the Application and click on the Add Application
* Click on the SAML 2.0.

//image
**Step 2: Setting  SP metadata**
* In General  Settings, enter App Name and click on Next.
* In SAML Settings, enter the following:

| Parameters | URL|
| ------------- | ------------- |
| Single Sign On URL | Root_URL/securityRealm/moSamlAuth  |
| Audience URI(SP Entity ID) | Root_URL/securityRealm/moSamlAuth  |
| Name ID Format | username |
| Application Username | Okta Username |
| Recipient URL and Destination URL| Root_URL|

  Root_URL can be like :http://localhost:8080
  
**Step3: Configuring Attributes**
* Configure Attribute Statement as follows:
 Add the username and email as an attribute.
//image
* Save the app settings.

**Step4: Assigning Groups and People**
* After creating and configuring the app go to the Assignment Tab in Okta.
* Here we select the people and groups you want to give access to login through this app. Assign this to the people/group you would like to give access to.
* After assigning the people/groups to your app go to Sign On tab.
* Click on view setup instructions to get the SAML Login URL (Single Sign on URL), Single Logout URL, IDP Entity ID, and X.509 Certificate.
* Copy the required information and paste in the respective field of jenkins plugin.
