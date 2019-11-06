# minorange as idp

miniOrange Single Sign On (SSO) for Jenkins  miniOrange also act as IDP for Jenkins. This solution ensures that you are ready to roll out secure access to your Jenkins using miniOrange within minutes.
Step 1: Configuring miniOrange as Identity Provider(IdP)
Go to miniOrange Admin console https://login.xecurify.com/moas and login with your miniOrange credentials.
From the left menu, go to Apps Manage Apps.
In the right upper corner, select Configure Apps.

In the search apps textbox, type Custom. Select Custom App.
Enter the following the textboxes.

Custom Application Name :
Any application Name
SP Entity ID or Issuer :
Root_URL/securityRealm/moSamlAuth
Audience URI :
Root_URL/securityRealm/moSamlAuth
*ACS URL :
Root_URL
NameID
Username

Root_URL can be like: http://localhost:8080

Attribute Mapping:
 Select Add Attribute and enter following details.
Attribute Name
Attribute Value
Username_attribute(Provided in Jenkins)
Username
Email_attribute(Provided in Jenkins)
E-mail Address

Step 2: Creating policy for the App
Select DEFAULT from the Group Name dropdown.
Enter Policy Name you would like to provide. Eg JenkinsPolicy.
Select Password from the First Factor Type dropdown.
Click on Save button to add the App

Save the app settings.


From the Configured App list, search your application name you just added and click on the Metadata link.
 Copy the metadata fields such as SAML Login URL ,X.509 Certificate etc. ,that are required to setup the jenkins plugin settings.

Paste the above URL in respective fields of Jenkins Miniorange Saml Plugin.


