# Ubuntu VPS amd64/arm64; builds are performed once, never on managed VPS.
FROM golang:1.26.1-alpine3.22@sha256:07e91d24f6330432729082bb580983181809e0a48f0f38ecde26868d4568c6ac AS engine
RUN apk add --no-cache git
WORKDIR /src
RUN git init && git remote add origin https://github.com/amnezia-vpn/amneziawg-go && git fetch --depth 1 origin 08fe3d33bbb116be09a6183d02609311b8b0c9e8 && git checkout --detach FETCH_HEAD
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -buildid=' -o /amneziawg-go .

FROM alpine:3.22.2@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412 AS tools
RUN apk add --no-cache git make build-base linux-headers
WORKDIR /tools
RUN git init && git remote add origin https://github.com/amnezia-vpn/amneziawg-tools && git fetch --depth 1 origin ee0f0a9aa34ff0a0da4b3433b9512781cfe02843 && git checkout --detach FETCH_HEAD
RUN make -C src && make -C src install DESTDIR=/out

FROM alpine:3.22.2@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412
RUN apk add --no-cache bash iproute2 iptables openresolv dumb-init curl
COPY --from=engine /amneziawg-go /usr/local/bin/amneziawg-go
COPY --from=tools /out/usr/ /usr/
COPY start.sh apply.sh validate.sh probe.sh /
RUN chmod 755 /*.sh
ENV WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go WG_SUDO=1
ENTRYPOINT ["/usr/bin/dumb-init","--","/start.sh"]
