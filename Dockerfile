FROM golang:1.23.0-bullseye

# Add non-root user
RUN addgroup --gid 1000 nonroot && \
    adduser --uid 1000 --gid 1000 --disabled-password nonroot

WORKDIR /home/nonroot/app 

USER nonroot

RUN go install github.com/jackc/tern/v2@latest && \
    go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest

CMD ["tail", "-f", "/dev/null"]