FROM alpine

RUN apk update && apk upgrade
RUN apk add --no-cache py-pip py-setuptools python-dev alpine-sdk && \
    pip install --upgrade pip

ENV WORKDIR /home/flypwd
RUN mkdir -p $WORKDIR
WORKDIR $WORKDIR

COPY . $WORKDIR
RUN pip install -r requirements.txt
RUN python setup.py install

CMD ["bash"]
