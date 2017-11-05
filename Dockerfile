FROM ubuntu:16.04

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y python3-pip
RUN apt-get install -y libmysqlclient-dev
RUN pip3 install --upgrade pip
RUN pip3 install mysqlclient

RUN apt-get install -y vim

