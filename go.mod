module github.com/k8snetworkplumbingwg/k8s-net-attach-def-controller

go 1.19

replace (
	k8s.io/api => k8s.io/api v0.25.4
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.25.4
	k8s.io/apimachinery => k8s.io/apimachinery v0.25.4
	k8s.io/apiserver => k8s.io/apiserver v0.25.4
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.25.4
	k8s.io/client-go => github.com/rancher/client-go v1.25.4-rancher1
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.25.4
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.25.4
	k8s.io/code-generator => k8s.io/code-generator v0.25.4
	k8s.io/component-base => k8s.io/component-base v0.25.4
	k8s.io/component-helpers => k8s.io/component-helpers v0.25.4
	k8s.io/controller-manager => k8s.io/controller-manager v0.25.4
	k8s.io/cri-api => k8s.io/cri-api v0.25.4
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.25.4
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.25.4
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.25.4
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.25.4
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.25.4
	k8s.io/kubectl => k8s.io/kubectl v0.25.4
	k8s.io/kubelet => k8s.io/kubelet v0.25.4
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.25.4
	k8s.io/metrics => k8s.io/metrics v0.25.4
	k8s.io/mount-utils => k8s.io/mount-utils v0.25.4
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.25.4
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.25.4
)

require (
	github.com/k8snetworkplumbingwg/network-attachment-definition-client v1.1.2-0.20220511184442-64cfb249bdbe
	github.com/pkg/errors v0.9.1
	gopkg.in/k8snetworkplumbingwg/multus-cni.v3 v3.9.2
	k8s.io/api v0.25.4
	k8s.io/apimachinery v0.25.4
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog/v2 v2.70.1
	k8s.io/kubernetes v1.25.4
	k8s.io/sample-controller v0.25.4
	k8s.io/utils v0.0.0-20220728103510-ee6ede2d64ed
)

require (
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/containernetworking/cni v0.8.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/emicklei/go-restful/v3 v3.8.0 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.5 // indirect
	github.com/go-openapi/swag v0.19.14 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/gnostic v0.5.7-v3refs // indirect
	github.com/google/go-cmp v0.5.8 // indirect
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/imdario/mergo v0.3.6 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/net v0.7.0 // indirect
	golang.org/x/oauth2 v0.0.0-20211104180415-d3ed0bb246c8 // indirect
	golang.org/x/sys v0.5.0 // indirect
	golang.org/x/term v0.5.0 // indirect
	golang.org/x/text v0.7.0 // indirect
	golang.org/x/time v0.0.0-20220210224613-90d013bbcef8 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/component-base v0.25.4 // indirect
	k8s.io/component-helpers v0.25.4 // indirect
	k8s.io/kube-openapi v0.0.0-20220803162953-67bda5d908f1 // indirect
	k8s.io/kube-scheduler v0.0.0 // indirect
	sigs.k8s.io/json v0.0.0-20220713155537-f223a00ba0e2 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
	sigs.k8s.io/yaml v1.2.0 // indirect
)
