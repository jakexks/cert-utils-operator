module github.com/redhat-cop/cert-utils-operator

go 1.16

require (
	github.com/go-logr/logr v0.4.0
	github.com/grantae/certinfo v0.0.0-20170412194111-59d56a35515b
	github.com/jetstack/cert-manager v1.6.1
	github.com/openshift/api v3.9.0+incompatible
	github.com/pavel-v-chernykh/keystore-go v2.1.0+incompatible
	github.com/redhat-cop/operator-utils v1.1.4
	github.com/stretchr/testify v1.7.0
	k8s.io/api v0.22.2
	k8s.io/apiextensions-apiserver v0.22.2
	k8s.io/apimachinery v0.22.2
	k8s.io/client-go v0.22.2
	k8s.io/kube-aggregator v0.22.0
	k8s.io/kubectl v0.22.1
	sigs.k8s.io/controller-runtime v0.10.1
)
