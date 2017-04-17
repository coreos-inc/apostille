FROM ubuntu

RUN apt-get update && apt-get -y upgrade && apt-get -y --fix-missing install bash           \
                                                                             git            \
                                                                             openssl        \
                                                                             curl           \
                                                                             tar            \
                                                                             python         \
                                                                             python-dev     \
                                                                             python-pip     \
                                                                             groff          \
                                                                             gzip           \
                                                                             uuid-runtime   \
                                                                             make           \
                                                                             jq

RUN pip install --upgrade awscli

RUN curl -LO https://kubernetes-helm.storage.googleapis.com/helm-v2.3.0-linux-amd64.tar.gz
RUN tar -zxvf helm-v2.3.0-linux-amd64.tar.gz
RUN chmod 700 linux-amd64/helm
RUN mv linux-amd64/helm /usr/local/bin/helm

RUN curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl
RUN chmod 700 ./kubectl
RUN mv ./kubectl /usr/local/bin/kubectl

ENV HELM_APP_REGISTRY_PLUGIN_VERSION 0.3.7
RUN curl -LO https://github.com/app-registry/helm-plugin/releases/download/v"${HELM_APP_REGISTRY_PLUGIN_VERSION}"/registry-helm-plugin-v"${HELM_APP_REGISTRY_PLUGIN_VERSION}"-dev-linux-x64.tar.gz
RUN mkdir -p ~/.helm/plugins/
RUN tar xzvf registry-helm-plugin-v"${HELM_APP_REGISTRY_PLUGIN_VERSION}"-dev-linux-x64.tar.gz -C ~/.helm/plugins/

