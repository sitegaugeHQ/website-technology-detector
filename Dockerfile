FROM apify/actor-node:22

COPY package*.json ./

RUN npm --quiet set progress=false \
    && npm install --omit=dev --omit=optional \
    && echo "Installed NPM packages:" \
    && (npm list --omit=dev --all || true) \
    && echo "Node.js version:" \
    && node --version \
    && echo "NPM version:" \
    && npm --version \
    && rm -r ~/.npm

COPY . ./

# Looking up host names and unpacking compressed pages share a small pool of threads; a larger pool keeps slow lookups from holding up the rest.
ENV UV_THREADPOOL_SIZE=24

# Node runs as the main process, with its heap sized to the memory of the run so that it tidies up before the limit is hit.
CMD ["sh", "-c", "exec node --max-old-space-size=$(( ${ACTOR_MEMORY_MBYTES:-${APIFY_MEMORY_MBYTES:-1024}} * 3 / 5 )) src/main.js"]
