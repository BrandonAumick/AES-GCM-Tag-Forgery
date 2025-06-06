FROM sagemath/sagemath:latest

USER root

COPY . /project
WORKDIR /project

RUN sage -pip install -r requirements.txt

CMD ["sage", "forge.sage"]