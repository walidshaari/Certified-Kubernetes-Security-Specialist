# Vagrant

We've created the automation to initialize cluster in your local machine using Vagrant, Ansible and kubeadm. You just need execute the following command and make sure Vagrant, Ansible are installed on your system.

```
$ vagrant up
# Once cluster done, you can ssh into each node
$ vagrant ssh master # or worker1 or worker2

# List all pods in the cluster
vagrant@master:~$ kubectl get po -A
```