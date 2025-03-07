FROM ubuntu:24.04

RUN apt-get update && apt-get install -y supervisor socat lib32z1 && apt-get clean

RUN useradd -md /home/bksec bksec

WORKDIR /home/bksec

COPY flag.txt /home/bksec/flag.txt
COPY chall .

RUN chown -R bksec:bksec /home/bksec
RUN chmod -R 555 /home/bksec

USER bksec

EXPOSE 1611

CMD socat -T 5 -d -d TCP-LISTEN:1611,reuseaddr,fork EXEC:"./chall"