#
# Copyright 2021 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM golang:1.26.3@sha256:2d6c80227255c3112a4d08e67ba98e58efd3846daf15d9d7d4c389565d881b1a AS builder
ENV APP_ROOT=/opt/app-root
ENV GOPATH=$APP_ROOT

WORKDIR $APP_ROOT/src/

# Copy sibling directories referenced in go.mod replace directives
COPY protobuf-specs $APP_ROOT/protobuf-specs/
COPY sigstore $APP_ROOT/sigstore/

ADD rekor/go.mod rekor/go.sum $APP_ROOT/src/
RUN go mod download

# Add source code
ADD rekor/cmd/ $APP_ROOT/src/cmd/
ADD rekor/pkg/ $APP_ROOT/src/pkg/

ARG SERVER_LDFLAGS
RUN go build -tags pq_circl -ldflags "${SERVER_LDFLAGS}" -o rekor-server ./cmd/rekor-server
RUN CGO_ENABLED=0 go build -tags pq_circl -gcflags "all=-N -l" -ldflags "${SERVER_LDFLAGS}" -o rekor-server_debug ./cmd/rekor-server
RUN go test -c -tags pq_circl -ldflags "${SERVER_LDFLAGS}" -cover -covermode=count -coverpkg=./... -o rekor-server_test ./cmd/rekor-server

# Multi-Stage production build
FROM golang:1.26.3@sha256:2d6c80227255c3112a4d08e67ba98e58efd3846daf15d9d7d4c389565d881b1a AS deploy

# Retrieve the binary from the previous stage
COPY --from=builder /opt/app-root/src/rekor-server /usr/local/bin/rekor-server

# Set the binary as the entrypoint of the container
ENTRYPOINT ["/usr/local/bin/rekor-server"]
CMD ["serve"]

# debug compile options & debugger
FROM deploy AS debug
RUN go install github.com/go-delve/delve/cmd/dlv@v1.22.1

# overwrite server and include debugger
COPY --from=builder /opt/app-root/src/rekor-server_debug /usr/local/bin/rekor-server

FROM deploy AS test
# overwrite server with test build with code coverage
COPY --from=builder /opt/app-root/src/rekor-server_test /usr/local/bin/rekor-server
