# minorange as IDP

miniOrange Single Sign On (SSO) for Jenkins  miniOrange also act as IDP for Jenkins. This solution ensures that you are ready to roll out secure access to your Jenkins using miniOrange within minutes.

## Step 1: Configuring miniOrange as Identity Provider(IdP) ##

* Go to miniOrange Admin console https://login.xecurify.com/moas and login with your miniOrange credentials.
* From the left menu, go to **Apps -> Manage Apps**.
* In the right upper corner, select Configure Apps.
 
 ![image_1](/docs/images/miniorange_as_idp/miniorange_manage_app_1.png)
 
* In the search apps textbox, type Custom. Select **Custom App**.
 
 ![image_2](/docs/images/miniorange_as_idp/miniorange_custom_app_3.png)
 
* Enter the following the textboxes.

| Field  | URL |         
| ------------- |:-------------:|
| Custom Application Name  | Any application Name | 
| Audience URI | Root_URL |  
| SP Entity ID | Root_URL |  
| Name ID Format | username | 
| Acs Url | Root_URL/securityRealm/moSamlAuth | 

Root_URL can be like: http://localhost:8080

![image_3](/docs/images/miniorange_as_idp/miniorange_app_edit_4.png)

**Attribute Mapping:**
* Select Add Attribute and enter following details.

| Attribute Name | Attribute Value | 
| --- | --- |
| Username_attribute(Provided in Jenkins) | Username | 
| Email_attribute(Provided in Jenkins) | E-mail Address | 

![image_4](/docs/images/miniorange_as_idp/miniorange_attribute_5.PNG)

## Step 2: Creating policy for the App ##
* Select **DEFAULT** from the Group Name dropdown.
* Enter Policy Name you would like to provide. Eg JenkinsPolicy.
* Select **Password** from the First Factor Type dropdown.
* Click on Save button to add the App

![image_5](/docs/images/miniorange_as_idp/miniorange_policy_6.png)

* Save the app settings.

## Step 3: Copy IDP Metadata ##
* From the Configured App list, search your application name you just added and click on the Metadata link.

![image_7](/docs/images/miniorange_as_idp/miniorange_idp_metadata_8.png)

 * Copy the metadata fields such as SAML Login URL ,X.509 Certificate etc. ,that are required to setup the jenkins plugin settings.
* Paste the above URL in respective fields of Jenkins Miniorange Saml Plugin.

![image_8](/docs/images/miniorange_as_idp/config_jenkins_9.png)
