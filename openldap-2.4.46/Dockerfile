FROM centos:latest

LABEL Author="Abhishek Shukla"

WORKDIR /ads

COPY . /ads/

RUN ["/bin/sh","./install_dep.sh"]

ENTRYPOINT ["/bin/sh","./entrypoint.sh"]

EXPOSE 389 636
