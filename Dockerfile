# Cross-compiles on the build machine's native platform (no emulation needed).
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /alertoba . \
    && mkdir /data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /alertoba /alertoba
# Owned by the nonroot user so a fresh volume is writable.
COPY --from=build --chown=nonroot:nonroot /data /data
ENV PORT=8080 DB_PATH=/data/alertoba.db
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/alertoba"]
