FROM node:24.11.1-alpine3.22@sha256:2867d550cf9d8bb50059a0fff528741f11a84d985c732e60e19e8e75c7239c43 AS web
WORKDIR /web
COPY web/package*.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.26.1-alpine3.22@sha256:07e91d24f6330432729082bb580983181809e0a48f0f38ecde26868d4568c6ac AS go
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /bin/api ./cmd/api && \
 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /bin/worker ./cmd/worker && \
 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /bin/telegram ./cmd/telegram && \
 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /bin/check ./cmd/check

FROM alpine:3.22.2@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412
RUN apk add --no-cache ca-certificates docker-cli && addgroup -g 10001 panel && adduser -D -u 10001 -G panel panel
WORKDIR /app
COPY --from=go /bin/api /bin/worker /bin/telegram /bin/check /usr/local/bin/
COPY --from=web /web/dist /app/web/dist
USER panel
EXPOSE 8080
CMD ["api"]
