# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage 1: compile the Go microservice into a static binary
# ---------------------------------------------------------------------------
FROM golang:1.26-alpine AS go-builder
WORKDIR /src/service
# Copy module files first to leverage Docker layer caching for dependencies.
COPY service/go.mod service/go.sum ./
RUN go mod download
COPY service/ ./
# CGO disabled => fully static binary that runs on a minimal base image.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/microservice .

# ---------------------------------------------------------------------------
# Stage 2: install production-only Node.js dependencies
# ---------------------------------------------------------------------------
FROM node:20-alpine AS node-deps
WORKDIR /app/backend
COPY backend/package.json backend/package-lock.json ./
# `npm ci` is deterministic and fails if the lockfile is out of sync.
RUN npm ci --omit=dev --no-audit --no-fund

# ---------------------------------------------------------------------------
# Final stage: Alpine + Node runtime carrying BOTH workloads
#   - Alpine gives syft a real OS package layer (apk/musl) to inventory.
#   - The Go binary and the Node app live side by side for the demo.
# ---------------------------------------------------------------------------
FROM node:20-alpine AS runtime
WORKDIR /app

# Run as the unprivileged user that the node image already ships with.
ENV NODE_ENV=production

# Go microservice binary.
COPY --from=go-builder /out/microservice /usr/local/bin/microservice

# Node backend (app code + resolved production node_modules).
COPY --from=node-deps /app/backend/node_modules ./backend/node_modules
COPY backend/package.json backend/index.js ./backend/

USER node
EXPOSE 3000 8080

# The Node backend is the container entrypoint for this PoC; the Go binary
# is present on PATH and can be launched on demand (or via a process manager).
CMD ["node", "backend/index.js"]
