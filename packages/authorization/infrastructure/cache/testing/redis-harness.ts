import { Redis } from "ioredis";

/** A Redis client the spec below owns, plus the teardown that stops it. */
export interface TestRedis {
  readonly client: Redis;
  readonly stop: () => Promise<void>;
}

/**
 * Connects to the Redis the environment points at, or reports that there is
 * none.
 *
 * `TEST_REDIS_URL` is the same variable the sessions deny-list suite uses
 * (Issue 088), and the CI `ci` job exports it alongside a Redis service
 * container — so this suite runs for real on every pull request rather than
 * skipping there. Locally, without the variable, the suite skips instead of
 * failing, which is what makes `pnpm test` work on a fresh clone.
 *
 * `REQUIRE_REDIS_TESTS=1` turns "no Redis" into a hard failure, so a
 * misconfigured CI service container can never be mistaken for a green run of a
 * suite that silently tested nothing.
 *
 * The Testcontainers fallback that `packages/identity`'s Postgres harness
 * (Issue 047) offers is deliberately **not** duplicated here: it would add a
 * Docker-lifecycle dependency to this package for a case CI already covers by
 * starting the container for the job.
 */
export async function startTestRedis(): Promise<TestRedis | undefined> {
  const url = process.env.TEST_REDIS_URL;
  if (url === undefined || url.trim() === "") {
    if (process.env.REQUIRE_REDIS_TESTS === "1") {
      throw new Error(
        "REQUIRE_REDIS_TESTS=1 but TEST_REDIS_URL is not set — the Redis-backed cache suite would have skipped.",
      );
    }
    return undefined;
  }

  const client = new Redis(url, {
    // Fail fast rather than buffering commands behind a connection that may
    // never arrive: a test that hangs is worse than a test that fails.
    lazyConnect: true,
    enableOfflineQueue: false,
    maxRetriesPerRequest: 2,
    retryStrategy: () => null,
  });
  client.on("error", () => {
    /* handled by the ping below */
  });

  try {
    await client.connect();
    await client.ping();
  } catch (error) {
    client.disconnect();
    if (process.env.REQUIRE_REDIS_TESTS === "1") {
      throw new Error(`REQUIRE_REDIS_TESTS=1 but ${url} is unreachable: ${String(error)}`);
    }
    return undefined;
  }

  return { client, stop: async () => client.disconnect() };
}
