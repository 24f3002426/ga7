const http = require("http");

const PORT = process.env.PORT || 3000;

const ACTION_SHA_RE = /^[0-9a-f]{40}$/;

function evaluateReleaseGate(body) {
  const violations = [];

  const workflow = body.workflow || {};
  const image = body.image || {};

  // 1. Permissions must be exactly:
  // contents: read
  // packages: write
  // id-token: none
  const expectedPermissions = {
    contents: "read",
    packages: "write",
    "id-token": "none",
  };

  const permissions = workflow.permissions || {};
  const permissionKeys = Object.keys(permissions);
  const expectedKeys = Object.keys(expectedPermissions);

  const permissionsExact =
    permissionKeys.length === expectedKeys.length &&
    expectedKeys.every(
      (key) =>
        Object.prototype.hasOwnProperty.call(permissions, key) &&
        permissions[key] === expectedPermissions[key]
    );

  if (!permissionsExact) {
    violations.push("EXCESS_PERMISSION");
  }

  // 2. Pull requests must use pull_request, never pull_request_target.
  if (body.event === "pull_request" && workflow.trigger !== "pull_request") {
    violations.push("UNSAFE_PR_TRIGGER");
  }

  // 3. Tests must pass, matrix must be complete, failFast must be false.
  if (
    workflow.testsPassed !== true ||
    workflow.matrixComplete !== true ||
    workflow.failFast !== false
  ) {
    violations.push("TESTS_INCOMPLETE");
  }

  //    a full 40-character lowercase hexadecimal SHA.
  const actions = Array.isArray(workflow.actions) ? workflow.actions : [];

  for (const action of actions) {
    if (action && action.owner === "actions") {
      continue;
    }

    if (!action || !ACTION_SHA_RE.test(action.ref || "")) {
      violations.push("MUTABLE_ACTION");
      break;
    }
  }

  // 5. Image must be multi-stage.
  if (image.multiStage !== true) {
    violations.push("SINGLE_STAGE_IMAGE");
  }

  // 6. Container must not run as root.
  if (image.runsAsRoot !== false) {
    violations.push("ROOT_RUNTIME");
  }

  // 7. Only "none" or "buildkit" secret handling is permitted.
  if (image.secretMode !== "none" && image.secretMode !== "buildkit") {
    violations.push("SECRET_IN_LAYER");
  }

  // 8. No critical vulnerabilities.
  if (image.criticalVulnerabilities !== 0) {
    violations.push("CRITICAL_CVE");
  }

  // 9. Image must be referenced by digest.
  if (image.digestPinned !== true) {
    violations.push("UNPINNED_IMAGE");
  }

  // 10. Production must be a push to refs/heads/main.
  if (
    body.target === "production" &&
    (body.event !== "push" || body.ref !== "refs/heads/main")
  ) {
    violations.push("INVALID_PRODUCTION_REF");
  }

  // 11. Production requires explicit environment approval.
  if (body.target === "production" && workflow.environmentApproval !== true) {
    violations.push("APPROVAL_REQUIRED");
  }

  return {
    decision: violations.length === 0 ? "promote" : "block",
    violations,
  };
}

function sendJson(res, statusCode, payload) {
  const json = JSON.stringify(payload);

  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(json),
  });

  res.end(json);
}

const server = http.createServer((req, res) => {
  if (req.method !== "POST" || req.url !== "/release-gate") {
    return sendJson(res, 404, {
      error: "Not found",
    });
  }

  let body = "";

  req.on("data", (chunk) => {
    body += chunk;

    // Basic protection against unnecessarily large requests.
    if (body.length > 1024 * 1024) {
      req.destroy();
    }
  });

  req.on("end", () => {
    try {
      const payload = JSON.parse(body);
      const result = evaluateReleaseGate(payload);

      sendJson(res, 200, result);
    } catch (error) {
      sendJson(res, 400, {
        error: "Invalid JSON",
      });
    }
  });
});

server.listen(PORT, () => {
  console.log(`Release gate listening on port ${PORT}`);
});

module.exports = {
  evaluateReleaseGate,
};
