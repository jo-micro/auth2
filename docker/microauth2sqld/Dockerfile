ARG DOCKER_IO=docker.io
ARG DOCKER_ORG_JO_MICRO=docker.io/jomicro

# STEP 1 build executable binary
FROM ${DOCKER_ORG_JO_MICRO}/builder:latest AS builder

# Create appuser (/etc/passwd entry for the runner container)
RUN useradd appuser

ARG VERSION
COPY . /code/
WORKDIR /code

ARG CACHEBUST=1
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -installsuffix cgo -ldflags="-w -s -X 'jochum.dev/jo-micro/auth2/cmd/microauth2sqld/config.Version=$VERSION'" -o /usr/local/bin/microauth2sqld jochum.dev/jo-micro/auth2/cmd/microauth2sqld

# STEP 2 build a small image
# start from busybox
FROM ${DOCKER_IO}/library/busybox:latest

LABEL maintainer="René Jochum <rene@jochum.dev>"

# Copy certs, passwd and binary from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /usr/local/bin/microauth2sqld /usr/local/bin/microauth2sqld
RUN chmod +x /usr/local/bin/microauth2sqld

COPY ./cmd/microauth2sqld/migrations /migrations

# Run as appuser
USER appuser

CMD [ "/usr/local/bin/microauth2sqld" ]