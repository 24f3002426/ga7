const test = require("node:test");
const assert = require("node:assert/strict");

const { evaluateReleaseGate } = require("./server");

const SAFE_ACTION_SHA =
  "0123456789abcdef0123456789abcdef01234567";

function safePayload(overrides = {}) {
  return {
    target: "preview",
    event: "pull_request",
    ref: "refs/heads/feature/test",
    workflow: {
      trigger: "pull_request",
      permissions: {
        contents: "read",
        packages: "write",
        "id-token": "none"
      },
      testsPassed: true,
      matrixComplete: true,
      failFast: false,
      actions: [
        {
          owner: "actions",
          name: "checkout",
          ref: "v4"
        },
        {
          owner: "docker",
          name: "build-push-action",
          ref: SAFE_ACTION_SHA
        }
      ]
    },
    image: {
      multiStage: true,
      runsAsRoot: false,
      secretMode: "none",
      criticalVulnerabilities: 0,
      digestPinned: true
    },
    ...overrides
  };
}

function assertViolations(payload, expected) {
  const result = evaluateReleaseGate(payload);

  assert.equal(
    result.decision,
    expected.length === 0 ? "promote" : "block"
  );

  assert.deepEqual(
    new Set(result.violations),
    new Set(expected)
  );
}

test("safe preview is promoted", () => {
  assertViolations(safePayload(), []);
});

test("extra permission is rejected", () => {
  const payload = safePayload();

  payload.workflow.permissions.admin = "write";

  assertViolations(payload, [
    "EXCESS_PERMISSION"
  ]);
});

test("wrong permission value is rejected", () => {
  const payload = safePayload();

  payload.workflow.permissions.packages = "read";

  assertViolations(payload, [
    "EXCESS_PERMISSION"
  ]);
});

test("pull_request_target is rejected", () => {
  const payload = safePayload();

  payload.workflow.trigger = "pull_request_target";

  assertViolations(payload, [
    "UNSAFE_PR_TRIGGER"
  ]);
});

test("failed tests are rejected", () => {
  const payload = safePayload();

  payload.workflow.testsPassed = false;

  assertViolations(payload, [
    "TESTS_INCOMPLETE"
  ]);
});

test("incomplete matrix is rejected", () => {
  const payload = safePayload();

  payload.workflow.matrixComplete = false;

  assertViolations(payload, [
    "TESTS_INCOMPLETE"
  ]);
});

test("failFast true is rejected", () => {
  const payload = safePayload();

  payload.workflow.failFast = true;

  assertViolations(payload, [
    "TESTS_INCOMPLETE"
  ]);
});

test("third-party tag is rejected", () => {
  const payload = safePayload();

  payload.workflow.actions[1].ref = "v6";

  assertViolations(payload, [
    "MUTABLE_ACTION"
  ]);
});

test("third-party uppercase SHA is rejected", () => {
  const payload = safePayload();

  payload.workflow.actions[1].ref =
    "0123456789ABCDEF0123456789ABCDEF01234567";

  assertViolations(payload, [
    "MUTABLE_ACTION"
  ]);
});

test("actions-owned tag is allowed", () => {
  const payload = safePayload();

  payload.workflow.actions = [
    {
      owner: "actions",
      name: "checkout",
      ref: "v4"
    }
  ];

  assertViolations(payload, []);
});

test("single-stage image is rejected", () => {
  const payload = safePayload();

  payload.image.multiStage = false;

  assertViolations(payload, [
    "SINGLE_STAGE_IMAGE"
  ]);
});

test("root runtime is rejected", () => {
  const payload = safePayload();

  payload.image.runsAsRoot = true;

  assertViolations(payload, [
    "ROOT_RUNTIME"
  ]);
});

test("arg secret is rejected", () => {
  const payload = safePayload();

  payload.image.secretMode = "arg";

  assertViolations(payload, [
    "SECRET_IN_LAYER"
  ]);
});

test("copy secret is rejected", () => {
  const payload = safePayload();

  payload.image.secretMode = "copy";

  assertViolations(payload, [
    "SECRET_IN_LAYER"
  ]);
});

test("BuildKit secret is allowed", () => {
  const payload = safePayload();

  payload.image.secretMode = "buildkit";

  assertViolations(payload, []);
});

test("critical vulnerability is rejected", () => {
  const payload = safePayload();

  payload.image.criticalVulnerabilities = 1;

  assertViolations(payload, [
    "CRITICAL_CVE"
  ]);
});

test("digest-less image is rejected", () => {
  const payload = safePayload();

  payload.image.digestPinned = false;

  assertViolations(payload, [
    "UNPINNED_IMAGE"
  ]);
});

test("production requires push to main", () => {
  const payload = safePayload();

  payload.target = "production";
  payload.event = "push";
  payload.ref = "refs/heads/release";

  payload.workflow.environmentApproval = true;

  assertViolations(payload, [
    "INVALID_PRODUCTION_REF"
  ]);
});

test("production requires approval", () => {
  const payload = safePayload();

  payload.target = "production";
  payload.event = "push";
  payload.ref = "refs/heads/main";

  assertViolations(payload, [
    "APPROVAL_REQUIRED"
  ]);
});

test("safe production is promoted", () => {
  const payload = safePayload();

  payload.target = "production";
  payload.event = "push";
  payload.ref = "refs/heads/main";
  payload.workflow.environmentApproval = true;

  assertViolations(payload, []);
});

test("multiple independent violations are all returned", () => {
  const payload = safePayload();

  payload.workflow.permissions = {
    contents: "write",
    packages: "read",
    "id-token": "write",
    deployments: "write"
  };

  payload.workflow.trigger = "pull_request_target";
  payload.workflow.testsPassed = false;
  payload.workflow.matrixComplete = false;
  payload.workflow.failFast = true;

  payload.workflow.actions = [
    {
      owner: "docker",
      name: "build-push-action",
      ref: "v6"
    }
  ];

  payload.image.multiStage = false;
  payload.image.runsAsRoot = true;
  payload.image.secretMode = "copy";
  payload.image.criticalVulnerabilities = 3;
  payload.image.digestPinned = false;

  assertViolations(payload, [
    "EXCESS_PERMISSION",
    "UNSAFE_PR_TRIGGER",
    "TESTS_INCOMPLETE",
    "MUTABLE_ACTION",
    "SINGLE_STAGE_IMAGE",
    "ROOT_RUNTIME",
    "SECRET_IN_LAYER",
    "CRITICAL_CVE",
    "UNPINNED_IMAGE"
  ]);
});

test("production can have multiple production-specific violations", () => {
  const payload = safePayload();

  payload.target = "production";
  payload.event = "push";
  payload.ref = "refs/heads/develop";

  assertViolations(payload, [
    "INVALID_PRODUCTION_REF",
    "APPROVAL_REQUIRED"
  ]);
});
