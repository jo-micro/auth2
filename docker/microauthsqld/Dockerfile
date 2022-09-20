# STEP 1 build executable binary
FROM registry.fk.jochum.dev/jo-micro/builder:latest AS builder

# Create appuser (/etc/passwd entry for the runner container)
RUN useradd appuser

ARG VERSION
COPY . /code/
WORKDIR /code
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -installsuffix cgo -ldflags="-w -s -X 'jochum.dev/jo-micro/auth2/cmd/microauthsqld/config.Version=$VERSION'" -o /usr/local/bin/microauthsqld jochum.dev/jo-micro/auth2/cmd/microauthsqld

# STEP 2 build a small image
# start from busybox
FROM busybox

LABEL maintainer="René Jochum <rene@jochum.dev>"

# Copy certs, passwd and binary from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /usr/local/bin/microauthsqld /usr/local/bin/microauthsqld
RUN chmod +x /usr/local/bin/microauthsqld

COPY ./cmd/microauthsqld/migrations /migrations

# Run as appuser
USER appuser

CMD [ "/usr/local/bin/microauthsqld" ]