K8S STIG Ansible Role
=========

Ansible playbook with a role to remediate a Kubernetes cluster based on the DISA Security Technical Implementation Guide (STIG) Benchmark for Kubernetes v1r8 [released on 26 Jan 2023] (<https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Kubernetes_V1R8_STIG.zip>). You can also view the stig here <https://cyber.trackr.live/stig/Kubernetes_STIG/1/0>

Requirements
------------

- Ansible v2.9+
- Kubernetes Nodes

Role Variables
--------------

Variables from defaults/main.yml

| Variable | Default |
| -------- | -------- |
| kubelet_certificate_authority_path | /etc/kubernetes/pki/ca.crt |
| kubelet_config_path | /var/lib/kubelet/config.yaml |
| kubelet_service_path | /lib/systemd/system/kubelet.service.d/10-kubeadm.conf |
| kubelet_sysconfig_path | /etc/sysconfig/kubelet |
| kube_proxy_kubeconfig_path | /etc/kubernetes/proxy.conf |
| kubelet_kubeconfig_path | /etc/kubernetes/kubelet.conf |
| admin_kubeconfig_path | /etc/kubernetes/admin.conf |
| controller_manager_manifest_path | /etc/kubernetes/manifests/kube-controller-manager.yaml |
| api_server_manifest_path | /etc/kubernetes/manifests/kube-apiserver.yaml |
| scheduler_manifest_path | /etc/kubernetes/manifests/kube-scheduler.yaml |
| etcd_manifest_path | /etc/kubernetes/manifests/etcd.yaml |
| pki_crt_dir | /etc/kubernetes/pki |
| pki_keys_dir | /etc/kubernetes/pki |
| manifests_dir | /etc/kubernetes/manifests |
| conf_dir | /etc/kubernetes |
| etcd_dir | /var/lib/etcd |
| pki_dir | /etc/kubernetes/pki |
| api_server_audit_policy_path | /etc/kubernetes/audit-policy.yaml |
| pod_security_policy_path | /etc/kubernetes/manifests/pod-security-policy.yaml |
| admission_control_config_path | /etc/kubernetes/admission-control-config.yaml |

Dependencies
------------

None.

Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    - hosts: servers
      vars:
        etcd_dir: /usr/lib/etcd
      roles:
        - cvockrodt.k8s_stig

License
-------

MIT

Author Information
------------------

This role was created in 2023 by [Casey Vockrodt](https://casey-vockrodt.com)
