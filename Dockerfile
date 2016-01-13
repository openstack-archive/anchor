FROM python:2.7
RUN pip install pecan
ADD . /code
WORKDIR /code
RUN pip install -e .
RUN openssl req -out CA/root-ca.crt \
  -keyout CA/root-ca-unwrapped.key \
  -newkey rsa:4096 \
  -subj "/CN=Anchor Test CA" \
  -nodes \
  -x509 \
  -days 365
RUN chmod 0400 CA/root-ca-unwrapped.key
ENTRYPOINT ["pecan", "serve", "/code/config.py"]
