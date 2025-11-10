FROM mitmproxy/mitmproxy:latest
WORKDIR /gateway
COPY requirements.txt /gateway/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY . /gateway
COPY ./local.env /gateway/.env
EXPOSE 8080
CMD ["mitmdump","-s", "/gateway/script/astrack.py","--proxyauth","user:pass","--listen-host","0.0.0.0","--listen-port","8080"]
