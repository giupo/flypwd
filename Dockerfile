FROM alpine

RUN apk update && apk upgrade
RUN apk add --no-cache py3-pip py3-setuptools python3-dev alpine-sdk && \
    pip3 install --upgrade pip

ENV WORKDIR /home/flypwd
RUN mkdir -p $WORKDIR
WORKDIR $WORKDIR

COPY . $WORKDIR
RUN pip3 install -r requirements.txt
RUN python3 setup.py install

CMD ["bash"]
