FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY . .
RUN apk add --no-cache git \
    && go build -o /govuln-scanner ./

FROM alpine:3.18
WORKDIR /app
COPY --from=builder /govuln-scanner /app/govuln-scanner
COPY templates ./templates
COPY static ./static
EXPOSE 8000
CMD ["/app/govuln-scanner", "-p", "8000"]
