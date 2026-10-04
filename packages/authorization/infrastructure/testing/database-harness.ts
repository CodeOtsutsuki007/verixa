import { execFileSync } from "node:child_process";
import { createConnection } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { PostgreSqlContainer, type StartedPostgreSqlContainer } from "@testcontainers/postgresql";
import { PrismaClient } from "@verixa/database";

const CONNECT_TIMEOUT_MS = 2_000;
const CONTAINER_START_TIMEOUT_MS = 120_000;

export interface TestDatabase {
  readonly prisma: PrismaClient;
  readonly stop: () => Promise<void>;
}

function canConnect(host: string, port: number): Promise<boolean> {
  return new Promise((resolveConnection) => {
    const socket = createConnection({ host, port });
    const finish = (reachable: boolean): void => {
      socket.removeAllListeners();
      socket.destroy();
      resolveConnection(reachable);
    };
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
    socket.setTimeout(CONNECT_TIMEOUT_MS, () => finish(false));
  });
}

async function existingDatabaseUrl(): Promise<string | undefined> {
  const configured = process.env["TEST_DATABASE_URL"];
  if (configured === undefined) return undefined;
  const url = new URL(configured);
  return (await canConnect(url.hostname, Number(url.port || 5432))) ? configured : undefined;
}

function dockerAvailable(): boolean {
  try {
    execFileSync("docker", ["info"], { stdio: "ignore", timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
}

function applyMigrations(databaseUrl: string): void {
  const databasePackageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../../database");
  execFileSync("pnpm", ["exec", "prisma", "migrate", "deploy"], {
    cwd: databasePackageRoot,
    env: { ...process.env, DATABASE_URL: databaseUrl },
    stdio: "ignore",
    shell: process.platform === "win32",
  });
}

export async function startTestDatabase(): Promise<TestDatabase | undefined> {
  const required = process.env["REQUIRE_DATABASE_TESTS"] === "1";
  const existing = await existingDatabaseUrl();
  if (existing !== undefined) {
    const prisma = new PrismaClient({ datasources: { db: { url: existing } } });
    return { prisma, stop: () => prisma.$disconnect() };
  }

  if (!dockerAvailable()) {
    if (required) {
      throw new Error(
        "REQUIRE_DATABASE_TESTS=1 but no database is available: TEST_DATABASE_URL is unset or " +
          "unreachable, and no Docker daemon was found for Testcontainers to use.",
      );
    }
    return undefined;
  }

  let container: StartedPostgreSqlContainer;
  try {
    container = await new PostgreSqlContainer("postgres:16-alpine")
      .withDatabase("verixa_test")
      .withUsername("verixa")
      .withPassword("verixa")
      .withStartupTimeout(CONTAINER_START_TIMEOUT_MS)
      .start();
  } catch (error) {
    if (required) throw error;
    return undefined;
  }

  const url = container.getConnectionUri();
  try {
    applyMigrations(url);
  } catch (error) {
    await container.stop();
    throw error;
  }

  const prisma = new PrismaClient({ datasources: { db: { url } } });
  return {
    prisma,
    stop: async () => {
      await prisma.$disconnect();
      await container.stop();
    },
  };
}
