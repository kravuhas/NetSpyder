FROM rust:1-slim-bookworm AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
 && cargo build --release --locked \
 && rm -rf src
COPY src ./src
COPY migrations ./migrations
COPY static ./static
RUN touch src/main.rs && cargo build --release --locked

FROM debian:bookworm-slim
RUN useradd --system --no-create-home --uid 10001 app
COPY --from=build /app/target/release/netspyder /usr/local/bin/netspyder
USER app
ENV BIND_ADDR=0.0.0.0:3000
EXPOSE 3000
CMD ["netspyder"]
