[![License: CC BY-SA 4.0](https://licensebuttons.net/l/by-sa/4.0/80x15.png)](https://creativecommons.org/licenses/by-sa/4.0/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)
# Certified Kubernetes Security Specialist - CKS  

Online curated resources that will help you prepare for taking the Kubernetes Certified Kubernetes Security Specialist **CKS** Certification exam.

- Please raise an issue, or make a pull request for fixes, new additions, or updates.

I will try to restrict the cross references of resources primarly to [kubernetes.io](https://kubernetes.io) as CNCF/Linux Foundation exam rules allows you search **kubernetes.io/{docs|blog}** and [kubernetes github repo](https://github.com/kubernetes) only. Youtube videos and other third party resources e.g. blogs will be provided as an optional complimentary material and any 3rd party material not allowed in the exam will be designated with :triangular_flag_on_post: in the curriculum sections below.

Ensure you have the right version of Kubernetes documentation selected (e.g. v1.19 as of 17th Nov GA announcement) especially for API objects and annotations, however for third party tools, you might find that you can still find references for them in old releases and blogs [e.g. Falco install](https://github.com/kubernetes/website/issues/24184).

* Icons/emoji legend
  - :clipboard:  Expand to see more content
  - :confused:   Verify, not best resource yet
  - :large_blue_circle: Good overall refence, can be used in the exam
  - :triangular_flag_on_post: External third-party resource, can not be used during exam
  - :pencil:  ToDo, item that needs further checking(todo list for future research/commits)
  

## Exam Brief 

Offical exam objectives you review and understand in order to pass the test.

* [CNCF Exam Curriculum repository ](https://github.com/cncf/curriculum/blob/master/CKS_Curriculum_%20v1.19.pdf)

- Duration : two (2) hours
- Number of questions: 15-20 hands-on performance based tasks
- Passing score: 67%
- Certification validity: two (2) years
- Prerequisite: valid CKA
- Cost: $300 USD, One (1) year exam eligibility, with a free retake within the year.

  *Linux Foundation offer several discounts around the year e.g. CyberMonday, Kubecon attendees among other special holidays/events*
## CKS repo topics overview

  - [X] [Cluster Setup - 10%](#cluster-setup---10)
  - [X] [Cluster Hardening - 15%](#cluster-hardening---15)
  - [X] [System Hardening - 15%](#system-hardening---15)
  - [X] [Minimize Microservice Vulnerabilities - 20%](#minimize-microservice-vulnerabilities---20)
  - [X] [Supply Chain Security - 20%](#supply-chain-security---20)
  - [X] [Monitoring, Logging and Runtime Security - 20%](#monitoring-logging-and-runtime-security---20)
  
  #### Extra helpful material
  
  - [x] [Slack](#slack)
  - [x] [Books](#books)
  - [x] [Youtube Videos](#youtube-videos)
  - [x] [Webinars](#webinars)
  - [x] [Containers and Kubernetes Security Training](#containers-and-kubernetes-security-training)
  - [x] [Extra Kubernetes security resources](generic-kubernetes-containers-security/Kubernetes.md)

<hr style="border:3px solid blue"> </hr>
<p align="center">
  <img width="360" src="kubernetes-security-specialist-logo-300x285.png">
</p>


### Cluster Setup - 10%
:large_blue_circle: [Securing a Cluster](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/) 

1. [Use Network security policies to restrict cluster level access](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
2. :triangular_flag_on_post: [Use CIS benchmark to review the security configuration of Kubernetes components](https://www.cisecurity.org/benchmark/kubernetes/)  (etcd, kubelet, kubedns, kubeapi)
3. Properly set up [Ingress objects with security control](https://kubernetes.io/docs/concepts/services-networking/ingress/#tls)
4. [Protect node metadata and endpoints](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#restricting-cloud-metadata-api-access)
5. [Minimize use of, and access to, GUI elements](https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/#accessing-the-dashboard-ui)
6. [Verify platform binaries before deploying](https://github.com/kubernetes/kubernetes/releases)

   <details><summary> :clipboard:  Kubernetes binaries can be verified by their digest **sha512 hash**  </summary>
  
   - checking the Kubernetes release page for the specific release
     -  checking the change log for the [images and their digests](https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.19.md#downloads-for-v1191)

   </details>


### Cluster Hardening - 15%

1. [Restrict access to Kubernetes API](https://kubernetes.io/docs/reference/access-authn-authz/controlling-access/)
2. [Use Role-Based Access Controls to minimize exposure](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
    * :triangular_flag_on_post: [handy site collects together articles, tools and the official documentation all in one place](https://rbac.dev/)
3. Exercise caution in using service accounts e.g. [disable defaults](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#use-the-default-service-account-to-access-the-api-server), minimize permissions on newly created ones
  
   <details><summary> :clipboard: opt out of automounting API credentials for a service account </summary>
  
   #### service account scope
   ```yaml
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     name: build-robot
   automountServiceAccountToken: false
   ```
   #### pod scope
   ```yaml
   apiVersion: v1
   kind: Pod
   metadata:
     name: cks-pod
   spec:
     serviceAccountName: default
     automountServiceAccountToken: false
   ```
   
   </details>


4. [Update Kubernetes frequently](https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-upgrade/)

### System Hardening - 15%

1. Minimize host OS footprint (reduce attack surface)

   <details><summary> :clipboard: :confused: Reduce host attack surface </summary>
 
   * [seccomp which stands for secure computing was originally intended as a means of safely running untrusted compute-bound programs](https://kubernetes.io/docs/tutorials/clusters/seccomp/)
   * [AppArmor can be configured for any application to reduce its potential host attack surface and provide greater in-depth defense.](https://kubernetes.io/docs/tutorials/clusters/apparmor/)
   * [PSP pod security policy enforces ](https://kubernetes.io/docs/concepts/policy/pod-security-policy/)
   * apply host updates
   * Install minimal required OS fingerprint
   * Protect access to data with permissions
     *  [Restirct allowed hostpaths](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems)

   </details>

2. Minimize IAM roles
   * :confused: [Access authentication and authorization](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
3. Minimize external access to the network

   <details><summary> :clipboard: :confused: if it means deny external traffic to outside the cluster?!! </summary>
  
   * not tested, however, the thinking is that all pods can talk to all pods in all name spaces but not to the outside of the cluster!!!

   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: deny-external-egress
   spec:
     podSelector: {}
     policyTypes:
     - Egress
     egress:
       to:
       - namespaceSelector: {}
     ```
 
    </details>
 
4. Appropriately use kernel hardening tools such as AppArmor, seccomp
   * [AppArmor](https://kubernetes.io/docs/tutorials/clusters/apparmor/)
   * [Seccomp](https://kubernetes.io/docs/tutorials/clusters/seccomp/)

### Minimize Microservice Vulnerabilities - 20%

1. Setup appropriate OS-level security domains e.g. using PSP, OPA, security contexts
   - [Pod Security Policies](https://kubernetes.io/docs/concepts/policy/pod-security-policy/)
   - [Open Policy Agent](https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/)
   - [Security Contexts](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
2. [Manage kubernetes secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
3. Use [container runtime](https://kubernetes.io/docs/concepts/containers/runtime-class/) sandboxes in multi-tenant environments (e.g. [gvisor, kata containers](https://github.com/kubernetes/enhancements/blob/5dcf841b85f49aa8290529f1957ab8bc33f8b855/keps/sig-node/585-runtime-class/README.md#examples))
4. [Implement pod to pod encryption by use of mTLS](https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/)
  - [ ] :pencil: check if service mesh is part of the CKS exam

### Supply Chain Security - 20%

1. Minimize base image footprint

   <details><summary> :clipboard: minimize base Image </summary>
  
   * Use distroless, UBI minimal, Alpine, or relavent to your app nodejs, python but the minimal build.
   * Do not include uncessary software not required for container during runtime
     - e.g build tools and utilities, troubleshooting and debug binaries.
       * :triangular_flag_on_post: [Learnk8s smaller docker images blog](https://learnk8s.io/blog/smaller-docker-images)
       * :triangular_flag_on_post: [GKE 7 best practices for building containers](https://cloud.google.com/blog/products/gcp/7-best-practices-for-building-containers)

   </details>

2. Secure your supply chain: [whitelist allowed image registries](https://kubernetes.io/blog/2019/03/21/a-guide-to-kubernetes-admission-controllers/#why-do-i-need-admission-controllers), sign and validate images
3. Use static analysis of user workloads (e.g. [kubernetes resources](https://kubernetes.io/blog/2018/07/18/11-ways-not-to-get-hacked/#7-statically-analyse-yaml), docker files)
4. [Scan images for known vulnerabilities](https://kubernetes.io/blog/2018/07/18/11-ways-not-to-get-hacked/#10-scan-images-and-run-ids)
   * :triangular_flag_on_post: [Aqua security Trivy](https://github.com/aquasecurity/trivy#quick-start)
   * :triangular_flag_on_post: [Anchore command line scans](https://github.com/anchore/anchore-cli#command-line-examples)
### Monitoring, Logging and Runtime Security - 20%

1. Perform behavioural analytics of syscall process and file activities at the host and container level to detect malicious activities
  - [Old kubernetes.io URL: install Falco on k8s 1.17](https://v1-17.docs.kubernetes.io/docs/tasks/debug-application-cluster/falco/)
	- :triangular_flag_on_post: [Falco Helm Chart](https://github.com/falcosecurity/charts/tree/master/falco)
	- :triangular_flag_on_post: [Falco Kubernetes manifests](https://github.com/falcosecurity/evolution/tree/master/deploy/kubernetes/kernel-and-k8s-audit)
	- :triangular_flag_on_post: [Falco installation guide](https://falco.org/docs/installation/)
	- :triangular_flag_on_post: [Detect CVE-2020-8557 using Falco](https://falco.org/blog/detect-cve-2020-8557/)
2. Detect threats within a physical infrastructure, apps, networks, data, users and workloads
3. Detect all phases of attack regardless where it occurs and how it spreads

   <details><summary> :clipboard:  Attack Phases </summary>
  
     - :triangular_flag_on_post:[Kubernetes attack martix Microsoft blog](https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/)
     - :triangular_flag_on_post: [MITRE attack framwork using Falco](https://sysdig.com/blog/mitre-attck-framework-for-container-runtime-security-with-sysdig-falco/)
     - :triangular_flag_on_post: [Lightboard video: Kubernetes attack matrix - 3 steps to mitigating the MITRE ATT&CK Techniques]()
     - :triangular_flag_on_post: [CNCF Webinar: Mitigating Kubernetes attacks](https://www.cncf.io/webinars/mitigating-kubernetes-attacks/)

   </details>

4. Perform deep analytical investigation and identification of bad actors within the environment
   - [Monitoring Kubernetes with sysdig](https://kubernetes.io/blog/2015/11/monitoring-kubernetes-with-sysdig/)
   - :triangular_flag_on_post:[CNCF Webinar: Getting started with container runtime security using Falco](https://youtu.be/VEFaGjfjfyc)
5. [Ensure immutability of containers at runtime](https://kubernetes.io/blog/2018/03/principles-of-container-app-design/)
6. [Use Audit Logs to monitor access](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/)

<hr style="border:3px solid blue"> </hr>

## Extra helpful material

### Slack

1. [Kubernetes Community - #cks-exam-prep](https://kubernetes.slack.com)
1. [Kubernauts Community - #cks](https://kubernauts-slack-join.herokuapp.com/)

### Books

1. [Aqua Security Liz Rice:Free Container Security Book](https://info.aquasec.com/container-security-book)
1. [Learn Kubernetes security: Securely orchestrate, scale, and manage your microservices in Kubernetes deployments](https://www.amazon.com/Learn-Kubernetes-Security-orchestrate-microservices/dp/1839216506)

### Youtube Videos

1. [Google/Ian Lewis: Kubernetes security best practices](https://youtu.be/wqsUfvRyYpw)
1. [Code in Action for the **book Learn Kubernetes Security** playlist](https://www.youtube.com/playlist?list=PLeLcvrwLe1859Rje9gHrD1KEp4y5OXApB)
1. [Kubernetes security concepts and demos](https://youtu.be/VjlvS-qiz_U)

### Containers and Kubernetes Security Training

1. [Killer.sh CKS practice exam](https://killer.sh/cks)       &#x27F9; use code **walidshaari** for **20%** discount
1. [Udemy Kubernetes CKS 2020 Complete Course and killer.sh Simulator](https://www.udemy.com/course/certified-kubernetes-security-specialist/)  - Special discount code **CKS-KILLER-SHELL** valid till 3rd Dec 2020
1. [Linux Foundation Kubernetes Security essentials LFS 260](https://training.linuxfoundation.org/training/kubernetes-security-essentials-lfs260/) -  available January 8, 2021.
1. [Linux Academy/ACloudGuru Kubernetes security](https://acloud.guru/learn/7d2c29e7-cdb2-4f44-8744-06332f47040e)
1. [Cloud native security defending containers and kubernetes](https://www.sans.org/event/stay-sharp-blue-team-ops-and-cloud-dec-2020/course/cloud-native-security-defending-containers-kubernetes)
1. [Tutorial: Getting Started With Cloud-Native Security - Liz Rice, Aqua Security & Michael Hausenblas](https://youtu.be/MisS3wSds40)
    - [hands-on tutorial](https://tutorial.kubernetes-security.info/)
1. [K21 academy CKS step by step activity hands-on-lab activity guide](https://k21academy.com/docker-kubernetes/certified-kubernetes-security-specialist-cks-step-by-step-activity-guide-hands-on-lab)
1. [Andrew Martin Control Plane Security training](https://control-plane.io/training/)

#### Other CKS related repos

1. [Stackrox CKS study guide](https://github.com/stackrox/Kubernetes_Security_Specialist_Study_Guide)
1. [Abdennour](https://github.com/abdennour/certified-kubernetes-security-specialist) - CKS curated resources
1. [Ibrahim Jelliti](https://github.com/ijelliti/CKSS-Certified-Kubernetes-Security-Specialist)  - CKS curated resources
1. [Viktor Vedmich](https://github.com/vedmichv/CKS-Certified-Kubernetes-Security-Specialist) - CKS curated resources
