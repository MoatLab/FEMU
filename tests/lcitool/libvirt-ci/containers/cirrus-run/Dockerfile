FROM docker.io/library/python:3.9-alpine

COPY cirrus-vars.py /usr/bin/cirrus-vars

#RUN pip3 install cirrus-run==1.0.1
RUN apk add git
RUN pip3 install 'cirrus-run @ git+https://github.com/pipo/cirrus-run@job-credits-2'
