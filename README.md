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
