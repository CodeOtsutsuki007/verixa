import { Result } from "@verixa/shared-kernel";
import { beforeEach, describe, expect, it } from "vitest";
import { VerificationRequest } from "../../domain/entities/verification-request.js";
import type { VerificationProvider, ProviderCheckResult } from "../ports/verification-provider.js";
import { InMemoryVerificationRequestRepository } from "../../infrastructure/fakes/in-memory-verification-request-repository.js";
import { RunAutomatedCheck } from "./run-automated-check.js";

class FakeVerificationProvider implements VerificationProvider {
  constructor(public resultToReturn: ProviderCheckResult | Error) {}

  async check(_request: VerificationRequest): Promise<ProviderCheckResult> {
    if (this.resultToReturn instanceof Error) {
      throw this.resultToReturn;
    }
    return this.resultToReturn;
  }
}

describe("RunAutomatedCheck", () => {
  let repository: InMemoryVerificationRequestRepository;
  let request: VerificationRequest;

  beforeEach(async () => {
    repository = new InMemoryVerificationRequestRepository();
    const createResult = VerificationRequest.register({
      subjectUserId: "user-1" as any,
      orgId: "org-1" as any,
      verificationType: "identity-document",
    });
    if (!Result.isOk(createResult)) throw new Error("fixture setup failed");
    request = createResult.value;
    const submitResult = request.transitionTo("submitted");
    if (!Result.isOk(submitResult)) throw new Error("fixture setup failed");
    await repository.save(request);
  });

  it("records a passing provider result and transitions to in_review", async () => {
    const providerResult: ProviderCheckResult = {
      outcome: "pass",
      score: 95,
      details: { match: true },
    };
    const provider = new FakeVerificationProvider(providerResult);
    const useCase = new RunAutomatedCheck(repository, provider);

    const result = await useCase.execute({ requestId: request.id });

    expect(Result.isOk(result)).toBe(true);
    if (!Result.isOk(result)) return;

    expect(result.value.request.status).toBe("in_review");
    expect(result.value.request.providerResult).toEqual(providerResult);
  });

  it("records a failing provider result and transitions to in_review", async () => {
    const providerResult: ProviderCheckResult = {
      outcome: "fail",
      score: 10,
      details: { match: false },
    };
    const provider = new FakeVerificationProvider(providerResult);
    const useCase = new RunAutomatedCheck(repository, provider);

    const result = await useCase.execute({ requestId: request.id });

    expect(Result.isOk(result)).toBe(true);
    if (!Result.isOk(result)) return;

    expect(result.value.request.status).toBe("in_review");
    expect(result.value.request.providerResult).toEqual(providerResult);
  });

  it("records an inconclusive provider result and transitions to in_review", async () => {
    const providerResult: ProviderCheckResult = {
      outcome: "inconclusive",
      score: 50,
      details: { reason: "blurry" },
    };
    const provider = new FakeVerificationProvider(providerResult);
    const useCase = new RunAutomatedCheck(repository, provider);

    const result = await useCase.execute({ requestId: request.id });

    expect(Result.isOk(result)).toBe(true);
    if (!Result.isOk(result)) return;

    expect(result.value.request.status).toBe("in_review");
    expect(result.value.request.providerResult).toEqual(providerResult);
  });

  it("catches provider errors/timeouts, records error annotation, and routes to in_review", async () => {
    const provider = new FakeVerificationProvider(new Error("Provider timeout"));
    const useCase = new RunAutomatedCheck(repository, provider);

    const result = await useCase.execute({ requestId: request.id });

    expect(Result.isOk(result)).toBe(true);
    if (!Result.isOk(result)) return;

    expect(result.value.request.status).toBe("in_review");
    expect(result.value.providerResult).toEqual({
      outcome: "inconclusive",
      score: 0,
      details: { error: "Provider timeout" },
    });
  });
});
