> Conjur + RHEL8 + Jenkins
> 
> Work in Progress
# 1. Setup MySQL database
- Setup MySQL database according to this guide: https://github.com/joetanx/conjur-mysql
# 2. Setup Conjur master
- Setup Conjur master according to this guide: https://github.com/joetanx/conjur-master
# 3. Setup Jenkins
- Install dependencies, import rpm key, install Jenkins
```console
yum -y install java-11-openjdk-devel
yum -y install https://download-ib01.fedoraproject.org/pub/epel/8/Everything/x86_64/Packages/d/daemonize-1.7.8-1.el8.x86_64.rpm
rpm --import https://pkg.jenkins.io/redhat/jenkins.io.key
yum -y install https://archives.jenkins-ci.org/redhat-stable/jenkins-2.319.2-1.1.noarch.rpm
```
- Download and import SSL certificate for Jenkins
- You should be using your own certificate in your own lab
```console
curl -L -o jenkins.vx.pfx https://github.com/joetanx/conjur-jenkins/raw/main/jenkins.vx.pfx
keytool -importkeystore -srckeystore jenkins.vx.pfx -destkeystore /usr/lib/jenkins/.keystore -deststoretype pkcs12
```
- Clean-up
```console
rm -f jenkins.vx.pfx
```
- Edit Jenkins configuration file to use HTTPS
```console
sed -i 's/JENKINS_PORT=\"8080\"/JENKINS_PORT=\"-1\"/' /etc/sysconfig/jenkins
sed -i 's/JENKINS_HTTPS_PORT=\"\"/JENKINS_HTTPS_PORT=\"8443\"/' /etc/sysconfig/jenkins
sed -i 's/JENKINS_HTTPS_KEYSTORE=\"\"/JENKINS_HTTPS_KEYSTORE=\"\/usr\/lib\/jenkins\/.keystore\"/' /etc/sysconfig/jenkins
sed -i 's/JENKINS_HTTPS_KEYSTORE_PASSWORD=\"\"/JENKINS_HTTPS_KEYSTORE_PASSWORD=\"cyberark\"/' /etc/sysconfig/jenkins
sed -i 's/JENKINS_HTTPS_LISTEN_ADDRESS=\"\"/JENKINS_HTTPS_LISTEN_ADDRESS=\"0.0.0.0\"/' /etc/sysconfig/jenkins
```
- Reload services, enable Jenkins to start on boot, start Jenkins service, allow Jenkins on firewall
```console
systemctl daemon-reload
systemctl enable jenkins
systemctl start jenkins
systemctl status jenkins
firewall-cmd --add-port 8443/tcp --permanent && firewall-cmd --reload
```
- Retrieve Jenkins initial admin password
```console
cat /var/log/jenkins/jenkins.log
```
or
```console
cat /var/lib/jenkins/secrets/initialAdminPassword
```
# 4. Conjur policies for Jenkins JWT
- Ref: https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Operations/Services/cjr-authn-jwt.htm
- `authn-jwt.yaml` - Configures the JWT authenticator
  - defines the authenticator webservice at `authn-jwt/jenkins`
  - mandatory authentication variables:
    - `provider-uri` - OIDC Provider URI. For applications that uses JWT providers that supports ODIC. Not used in this demo.
    - `jwks-uri` - JSON Web Key Set (JWKS) URI
  - defines the options authentication variables:
    - `token-app-property` - The JWT claim to be used to identify the application. This demo uses the `identity` claim from Jenkins, which is configured in the Conjur Secrets Plugin under Jenkins to use `jenkins_name` as identity. This variable is always used together with `identity-path`. 
    - `identity-path` - The Conjur policy path where the app ID (`host`) is defined in Conjur policy. The app IDs in `authn-jet-hosts.yaml are created under `jwt-apps/jenkins`, so the `identity-path` will be `jwt-apps/jenkins`.
    - `issuer` - URI of the JWT issuer. For Jenkins this is `https://<Jenkins-URL>/jwtauth/conjur-jwk-set`. This is included in `iss` claim in the JWT token claims.
    - `enforced-claims` - List of claims that are enforced (meaning must be included in the JWT token claims). Not used in this demo.
    - `claim-aliases` - Map claims to aliases. Not used in this demo.
    - `audience` - JWT audience configured in the Conjur Secrets Plugin under Jenkins. This is configured as the host name of my Jenkins host `jenkins.vx` in this demo.
  - defines `consumers` group - applications that are authorized to authenticate using this JWT authenticator are added to this group
  - defines `operators` group - users who are authorized to check the status of this JWT authenticator are added to this group
- `authn-jwt-hosts.yaml`
  - `jwt-apps/jenkins` - policy name, this is also the `identity-path` of the app IDs
  - applications `AWS-Access-Key-Demo` and  are configured
    - the `id` of the `host` corresponds to the `token-app-property`
    - annotations of the `host` are optional and corresponds to claims in the JWT token claims - the more annotations/claims configured, the more precise and secure the application authentication
    - the host layer is granted as a member of the `consumer` group defined in `authn-jwt.yaml` to authorize them to authenticate to the JWT authenticator
- `app-vars.yaml`
  - targets `world_db` and `aws_api` are defined with the respective secret variables
  - applications `MySQL-Demo`is granted access to `world_db` secrets, and applications `AWS-Access-Key-Demo` is granted access to `aws_api` secrets
