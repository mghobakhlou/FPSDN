FROM ubuntu:22.04
WORKDIR /app

COPY benchmarks ./benchmarks 
COPY Expriments ./Expriments
COPY FPSDN ./FPSDN
COPY netkat ./netkat
COPY src ./src



ENV DEBIAN_FRONTEND=noninteractive


RUN apt-get update && \
    apt-get install -y git python3-pip tshark libncurses5 opam wget unzip && \
    pip3 install pandas pyshark matplotlib numpy networkx


RUN cd netkat && \
    opam init -y && \
    eval $(opam env) && \
    opam install printbox-text printbox-html -y && \
    opam install mparser=1.2.3 -y && \
    opam install . --deps-only -y && \
    opam install core_unix -y && \
    eval $(opam env) && \
    make && \
    cd ..

RUN wget http://maude.cs.illinois.edu/w/images/3/38/Maude-3.1-linux.zip && \
    unzip Maude-3.1-linux.zip && \
    rm Maude-3.1-linux.zip && \
    cd maude-3.1 && \
    chmod +x maude.linux64 && \
    cd ..


COPY run_test.sh /app/
COPY run_fault_scenarios.sh /app/
COPY run_extraction_rules_expriments.sh /app/
COPY dnk.py /app/


RUN chmod +x /app/run_test.sh /app/run_fault_scenarios.sh /app/run_extraction_rules_expriments.sh

