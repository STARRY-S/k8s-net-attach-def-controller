FROM golang:1.16-alpine as builder

ADD . /usr/src/k8s-net-attach-def-controller

ENV HTTP_PROXY $http_proxy
ENV HTTPS_PROXY $https_proxy
ENV GO111MODULE off
RUN apk add --update make && \
    cd /usr/src/k8s-net-attach-def-controller && \
    make clean && \
    make build

RUN ls -al /usr/src/k8s-net-attach-def-controller

FROM registry.suse.com/bci/bci-base:15.4
COPY --from=builder /usr/src/k8s-net-attach-def-controller/build/k8s-net-attach-def-controller /usr/bin/

ENTRYPOINT ["/usr/bin/k8s-net-attach-def-controller"]
