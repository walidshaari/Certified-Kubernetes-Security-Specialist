# Certified Kubernetes Security Specialist - CKS  

<p align="center">
  <img width="270" src="kubernetes-security-specialist-logo-300x285.png">
</p>

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)
[![License: CC BY-SA 4.0](https://licensebuttons.net/l/by-sa/4.0/80x15.png)](https://creativecommons.org/licenses/by-sa/4.0/)

Online curated resources that will help you prepare for taking the Kubernetes Certified Kubernetes Security Specialist **CKS** Certification exam.

- Please raise an issue, or make a pull request for fixes, new additions, or updates.

Resources are primarly cross referenced back to the [allowed CKS sites](#urls-allowed-in-the-extra-single-tab) during the exam as per CNCF/Linux Foundation exam allowed search rules. Videos and other third party resources e.g. blogs will be provided as an optional complimentary material and any 3rd party material not allowed in the exam will be designated with :triangular_flag_on_post: in the curriculum sections below.

Ensure you have the right version of Kubernetes documentation selected (e.g. v1.19 as of 17th Nov GA announcement) especially for API objects and annotations, however for third party tools, you might find that you can still find references for them in old releases and blogs [e.g. Falco install](https://github.com/kubernetes/website/issues/24184).

* Icons/emoji legend
  - :clipboard:  Expand to see more content
  - :confused:   Verify, not best resource yet
  - :large_blue_circle: Good overall refence, can be used in the exam
  - :triangular_flag_on_post: External third-party resource, can not be used during exam
  - :pencil:  To-do, item that needs further checking(todo list for future research/commits)

## Exam Brief 

Offical exam objectives you review and understand in order to pass the test.

* [CNCF Exam Curriculum repository ](https://github.com/cncf/curriculum/blob/master/CKS_Curriculum_%20v1.19.pdf)

- **Duration** : two (2) hours
- **Number of questions**: 15-20 hands-on performance based tasks
- **Passing score**: 67%
- **Certification validity**: two (2) years
- **Prerequisite**: valid CKA
- **Cost**: $300 USD, One (1) year exam eligibility, with a free retake within the year.

  *Linux Foundation offer several discounts around the year e.g. CyberMonday, Kubecon attendees among other special holidays/events*

## URLs allowed in the extra single tab
From Chrome or Chromium browser to open one (1) additional tab in order to access Kubernetes Documentation: 
- https://kubernetes.io/docs and their subdomains
- https://github.com/kubernetes and their subdomains
- https://kubernetes.io/blog and their subdomains
- [Sysdig documentation](https://docs.sysdig.com)
- [Falco documentation](https://falco.org/docs)
- [App Armor documentation](https://gitlab.com/apparmor/apparmor/-/wikis/Documentation)
  
  *This includes all available language translations of these pages (e.g. https://kubernetes.io/zh/docs)*

## CKS repo topics overview

  - [X] [Cluster Setup - 10%](#cluster-setup---10)
  - [X] [Cluster Hardening - 15%](#cluster-hardening---15)
  - [X] [System Hardening - 15%](#system-hardening---15)
  - [X] [Minimize Microservice Vulnerabilities - 20%](#minimize-microservice-vulnerabilities---20)
  - [X] [Supply Chain Security - 20%](#supply-chain-security---20)
  - [X] [Monitoring, Logging and Runtime Security - 20%](#monitoring-logging-and-runtime-security---20)
  
  #### Extra helpful material
  
  - [x] [Slack](#slack)
  - [x] [Books](generic-kubernetes-containers-security/Kubernetes.md#books)
  - [x] [Youtube Videos](generic-kubernetes-containers-security/Kubernetes.md#youtube-videos)
  - [x] [Containers and Kubernetes Security Training](generic-kubernetes-containers-security/Kubernetes.md#containers-and-kubernetes-security-training)

---

### Cluster Setup - 10%

1. [Use Network security policies to restrict cluster level access](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
2. [Use CIS benchmark to review the security configuration of Kubernetes components (etcd, kubelet, kubedns, kubeapi)](https://www.cisecurity.org/benchmark/kubernetes/)  
     - [Kube-bench](https://github.com/aquasecurity/kube-bench) - Checks whether Kubernetes is deployed securely by running the checks documented in the CIS Kubernetes Benchmark.
3. [Properly set up Ingress objects with security control](https://kubernetes.io/docs/concepts/services-networking/ingress/#tls)
4. [Protect node metadata and endpoints](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#restricting-cloud-metadata-api-access)

    - <details><summary>Using Network policy to restrict pods access to cloud metadata for example AWS cloud</summary>
      ```yaml
      apiVersion: networking.k8s.io/v1
      kind: NetworkPolicy
      metadata:
        name: deny-only-cloud-metadata-access
      spec:
        podSelector: {}
        policyTypes:
        - Egress
        egress:
        - to:
          - ipBlock:
            cidr: 0.0.0.0/0
            except:
            - 169.254.169.254/32  # metadata IP address that can be used to access internal resources
      ```
    </details>
 
5. [Minimize use of, and access to, GUI elements](https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/#accessing-the-dashboard-ui)
6. [Verify platform binaries before deploying](https://github.com/kubernetes/kubernetes/releases)
    - Kubernetes binaries can be verified by their digest **sha512 hash**.
    - Checking the Kubernetes release page for the specific release.
    - Checking the change log for the [images and their digests](https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.19.md#downloads-for-v1191)

### Cluster Hardening - 15%

1. [Restrict access to Kubernetes API](https://kubernetes.io/docs/reference/access-authn-authz/controlling-access/)
    - [Control anonymous requests to Kube-apiserver](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-requests)
    - [Non secure access to the kube-apiserver](https://kubernetes.io/docs/concepts/security/controlling-access/#api-server-ports-and-ips)
2. [Use Role-Based Access Controls to minimize exposure](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
3. [Exercise caution in using service accounts e.g. disable defaults, minimize permissions on newly created ones](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
4. [Update Kubernetes frequently](https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-upgrade/)

### System Hardening - 15%

1. Minimize host OS footprint (reduce attack surface)
    - [Restrict a Container's Syscalls with Seccomp](https://kubernetes.io/docs/tutorials/clusters/seccomp/)
    - [Restrict a Container's Access to Resources with AppArmor](https://kubernetes.io/docs/tutorials/clusters/apparmor/)
    - [Configure a Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

2. [Minimize IAM roles](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
3. [Minimize external access to the network](https://kubernetes.io/docs/concepts/services-networking/network-policies/#default-deny-all-egress-traffic)
4. Appropriately use kernel hardening tools such as [AppArmor](https://kubernetes.io/docs/tutorials/clusters/apparmor/), [seccomp](https://kubernetes.io/docs/tutorials/clusters/seccomp/)

### Minimize Microservice Vulnerabilities - 20%

1. Setup appropriate OS-level security domains e.g. using [PSP](https://kubernetes.io/docs/concepts/policy/pod-security-policy/), [OPA](https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/), [security contexts](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
2. [Manage kubernetes secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
3. Use [container runtime](https://kubernetes.io/docs/concepts/containers/runtime-class/) sandboxes in multi-tenant environments (e.g. [gvisor, kata containers](https://github.com/kubernetes/enhancements/blob/5dcf841b85f49aa8290529f1957ab8bc33f8b855/keps/sig-node/585-runtime-class/README.md#examples))
4. [Implement pod to pod encryption by use of mTLS](https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/)

### Supply Chain Security - 20%

1. Minimize base image footprint

   - <details><summary> :clipboard: Minimize base Image </summary>
      * Use distroless, UBI minimal, Alpine, or relavent to your app nodejs, python but the minimal build.
      * Do not include uncessary software not required for container during runtime e.g build tools and utilities, troubleshooting and debug binaries.
        * :triangular_flag_on_post: [Learnk8s: 3 simple tricks for smaller Docker images](https://learnk8s.io/blog/smaller-docker-images)
        * :triangular_flag_on_post: [GKE 7 best practices for building containers](https://cloud.google.com/blog/products/gcp/7-best-practices-for-building-containers)
    </details>

2. Secure your supply chain: [whitelist allowed image registries](https://kubernetes.io/blog/2019/03/21/a-guide-to-kubernetes-admission-controllers/#why-do-i-need-admission-controllers), sign and validate images
3. Use static analysis of user workloads (e.g. [kubernetes resources](https://kubernetes.io/blog/2018/07/18/11-ways-not-to-get-hacked/#7-statically-analyse-yaml), docker files)
4. [Scan images for known vulnerabilities](https://kubernetes.io/blog/2018/07/18/11-ways-not-to-get-hacked/#10-scan-images-and-run-ids)
    * [Trivy]( https://github.com/aquasecurity/trivy)

### Monitoring, Logging and Runtime Security - 20%

1. Perform behavioural analytics of syscall process and file activities at the host and container level to detect malicious activities
2. Detect threats within a physical infrastructure, apps, networks, data, users and workloads
3. Detect all phases of attack regardless where it occurs and how it spreads
4. Perform deep analytical investigation and identification of bad actors within the environment
5. [Ensure immutability of containers at runtime](https://kubernetes.io/blog/2018/03/principles-of-container-app-design/)
6. [Use Audit Logs to monitor access](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/)

---

## Extra helpful material

### Slack

1. [Kubernetes Community - #cks-exam-prep](https://kubernetes.slack.com)
1. [Kubernauts Community - #cks](https://kubernauts-slack-join.herokuapp.com/)

#### Other CKS related resources

1. [Stackrox CKS study guide](https://github.com/stackrox/Kubernetes_Security_Specialist_Study_Guide) - Brief and informative study guide from [Stackrox @mfosterrox](https://www.stackrox.com/authors/mfoster/)
1. [Kim's CKS Challenge series](https://github.com/killer-sh/cks-challenge-series) - also posted on medium @ https://wuestkamp.medium.com/
1. [Abdennour](https://github.com/abdennour/certified-kubernetes-security-specialist)
1. [Ibrahim Jelliti](https://github.com/ijelliti/CKSS-Certified-Kubernetes-Security-Specialist)
1. [Viktor Vedmich](https://github.com/vedmichv/CKS-Certified-Kubernetes-Security-Specialist)

## Contributors

<table>
  <tr>
  <td align="center"><a href="https://github.com/walidshaari"><img alt="walidshaari" src="https://avatars.githubusercontent.com/u/1757428?s=400&v=4" width="100" /><br />walidshaari</a></td>
  <td align="center"><a href="https://github.com/myugan"><img alt="myugan" src="https://avatars3.githubusercontent.com/u/20453528?v=4" width="100" /><br />myugan</a></td>
  <td align="center"><a href="https://github.com/CloudGrimm"><img alt="CloudGrimm" src="https://avatars2.githubusercontent.com/u/22336209?v=4" width="100" /><br />CloudGrimm</a></td>
  <td align="center"><a href="https://github.com/fntlnz"><img alt="sfntlnz" src="https://avatars0.githubusercontent.com/u/3083633?v=4" width="100" /><br />fntlnz</a></td>
  <td align="center"><a href="https://github.com/saiyam1814"><img alt="saiyam1814" src="https://avatars2.githubusercontent.com/u/8190114?v=4" width="100" /><br />saiyam1814</a></td>
  <td align="center"><a href="https://github.com/tylerauerbeck"><img alt="tylerauerbeck" src="https://avatars3.githubusercontent.com/u/29497147?v=4" width="100" /><br />tylerauerbeck</a></td>
  <td align="center"><a href="https://github.com/pmmalinov01"><img alt="pmmalinov01" src="https://avatars3.githubusercontent.com/u/59862813?v=4" width="100" /><br />pmmalinov01</a></td>
  <td align="center"><a href="https://github.com/pocteo-labs"><img alt="pocteo-labs" src="https://avatars3.githubusercontent.com/u/60813186?v=4" width="100" /><br />pocteo-labs</a></td>
  </tr>
</table>