> Conjur + RHEL8 + Jenkins
> 
> Work in Progress
# 1. Setup MySQL database
- Install MySQL server
- Enable MySQL server to start with system
- Allow MySQL communiction on firewalld
```console
yum -y install mysql-server
systemctl enable --now mysqld
firewall-cmd --permanent --add-service mysql && firewall-cmd --reload
```
- Download sample world database
```console
curl -L -o world-db.tar.gz https://downloads.mysql.com/docs/world-db.tar.gz
tar xvf world-db.tar.gz
```
- Load sample world database
- Create MySQL account to be used for the sample application
```console
mysql -u root
CREATE USER 'cityapp'@'%' IDENTIFIED BY 'Cyberark1';
GRANT ALL PRIVILEGES ON *.* TO 'cityapp'@'%';
SOURCE /root/world-db/world.sql
SHOW DATABASES;
SELECT user,host FROM mysql.user;
QUIT;
```
- Verify
```console
ls -l /var/lib/mysql/world
```
- Clean-up
```console
rm -f world-db.tar.gz
rm -rf world-db
```
# 2. Setup Conjur Master
- Install podman
```console
yum -y installl podman
```
- Obtain the Conjur container image from CyberArk
- Upload the Conjur container image to the container host
```console
podman load -i conjur-appliance_12.4.1.tar.gz
```
- Clean-up
```console
rm -f conjur-appliance_12.4.1.tar.gz
```
- Stage the volume mounts and download the conjur configuration file
```console
mkdir -p /opt/cyberark/dap/{security,config,backups,seeds,logs}
curl -L -o /opt/cyberark/dap/config/conjur.yml https://github.com/joetanx/conjur-k8s/raw/main/conjur.yml
```
- Download the Conjur CLI and add execute permissions
- Ref: https://github.com/cyberark/conjur-api-python3/releases
```console
curl -L -o conjur-cli-rhel-8.tar.gz https://github.com/cyberark/conjur-api-python3/releases/download/v7.1.0/conjur-cli-rhel-8.tar.gz
tar xvf conjur-cli-rhel-8.tar.gz
mv conjur /usr/local/bin/
```
- Clean-up
```console
rm -f conjur-cli-rhel-8.tar.gz
```
- Run the Conjur container
```console
podman run --name conjur -d \
--restart=unless-stopped \
--security-opt seccomp=unconfined \
-p "443:443" -p "444:444" -p "5432:5432" -p "1999:1999" \
--log-driver journald \
-v /opt/cyberark/dap/config:/etc/conjur/config:Z \
-v /opt/cyberark/dap/security:/opt/cyberark/dap/security:Z \
-v /opt/cyberark/dap/backups:/opt/conjur/backup:Z \
-v /opt/cyberark/dap/seeds:/opt/cyberark/dap/seeds:Z \
-v /opt/cyberark/dap/logs:/var/log/conjur:Z \
registry.tld/conjur-appliance:12.4.1
```
- Setup the Conjur container as master
- Edit the admin account password in `-p` option and the Conjur account (`cyberark`) according to your environment
```console
podman exec conjur evoke configure master --accept-eula -h conjur.vx --master-altnames "conjur.vx" -p CyberArk123! cyberark
```
- Run the Conjur container as systemd service and configure it to setup with container host
- Ref: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux_atomic_host/7/html/managing_containers/running_containers_as_systemd_services_with_podman
```console
podman generate systemd conjur --name --container-prefix="" --separator="" > /etc/systemd/system/conjur.service
systemctl enable conjur
```
- Setup Conjur certificates
- The `conjur-certs.tgz` include CA, Master and follower certificates for my lab use, you should generate your own certificates
- Refer to https://github.com/joetanx/conjur-k8s/blob/main/generate-conjur-certificates.md for a guide to generate your own certificates
> Note: In event of "error: cert already in hash table", ensure that conjur/follower certificates do not contain the CA certificate
```console
curl -L -o conjur-certs.tgz https://github.com/joetanx/conjur-k8s/raw/main/conjur-certs.tgz
podman cp conjur-certs.tgz conjur:/tmp/
podman exec conjur tar xvf /tmp/conjur-certs.tgz -C /tmp/
podman exec conjur evoke ca import --root /tmp/central.pem
podman exec conjur evoke ca import --key /tmp/follower.default.svc.cluster.local.key /tmp/follower.default.svc.cluster.local.pem
podman exec conjur evoke ca import --key /tmp/conjur.vx.key --set /tmp/conjur.vx.pem
```
- Clean-up
```console
podman exec conjur /bin/sh -c "rm -f /tmp/conjur-certs.tgz /tmp/*.pem /tmp/*key"
rm -f conjur-certs.tgz
```
- Initialize Conjur CLI and login to conjur
```console
conjur init -u https://conjur.vx
conjur login -i admin -p CyberArk123!
```
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
curl -L -o conjur.vx.pfx https://github.com/joetanx/conjur-jenkins/raw/main/conjur.vx.pfx
keytool -importkeystore -srckeystore conjur.vx.pfx -destkeystore /usr/lib/jenkins/.keystore -deststoretype pkcs12
```
- Clean-up
```console
rm -f conjur.vx.pfx
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
