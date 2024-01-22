#!/bin/bash

make image

docker image tag cnrancher/k8s-net-attach-def-controller:latest hxstarrys/k8s-net-attach-def-controller:latest
docker push hxstarrys/k8s-net-attach-def-controller:latest
