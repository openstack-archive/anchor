FROM python:2.7
RUN pip install pecan
ADD . /code
WORKDIR /code
RUN pip install -e .
ENTRYPOINT ["python","container_bootstrap.py"]
