FROM registry.suse.com/bci/bci-base:15.4

ARG ARCH=amd64

COPY bin/k8s-net-attach-def-controller /usr/bin/
ENTRYPOINT ["/usr/bin/k8s-net-attach-def-controller"]
