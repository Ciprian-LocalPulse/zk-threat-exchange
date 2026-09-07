# zk-threat-exchange :: heuristics-engine image
# Author: Ciprian Ștefan Pleșca
FROM julia:1.10-bookworm
LABEL maintainer="Ciprian Ștefan Pleșca"
WORKDIR /app
COPY heuristics-engine/Project.toml ./Project.toml
COPY heuristics-engine/src ./src
COPY heuristics-engine/test ./test
RUN julia --project=. -e 'using Pkg; Pkg.instantiate()'
CMD ["julia", "--project=.", "-e", "include(\"test/runtests.jl\")"]
