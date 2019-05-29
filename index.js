require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const { spawn } = require("child_process");

const app = express();
// we want to make sure that we can verify the signiture correctly
app.use(bodyParser.raw({ type: "application/json" }));

const { NODE_ENV, PORT, WEBHOOK_SECRET, WEBHOOK_REF, DEPLOY_DIRECTORY, DEPLOY_SCRIPT } = {
  NODE_ENV: "development",
  PORT: 18498,
  WEBHOOK_SECRET: "secret",
  WEBHOOK_REF: "refs/heads/master",
  DEPLOY_DIRECTORY: "/home",
  DEPLOY_SCRIPT: "./deploy.sh",

  // this will override any defaults above
  ...process.env,
};

function verifyPostData(req, res, next) {
  if (WEBHOOK_SECRET) {
    const payload = req.body.toString();

    if (!payload) {
      return next("Request body empty");
    }

    const hmac = crypto.createHmac("sha1", WEBHOOK_SECRET);
    const digest = "sha1=" + hmac.update(payload).digest("hex");

    const checksum = req.headers["x-hub-signature"];
    if (!checksum || !digest || checksum !== digest) {
      return next(`Request body digest (${digest}) did not match X-Hub-Signature (${checksum})`);
    }
  }

  return next();
}

app.post("/webhooks/github", verifyPostData, (req, res, next) => {
  const body = JSON.parse(req.body);
  console.log("body", body);

  if (req.headers["x-github-event"] === "ping") {
    res.sendStatus(200);
  } else {
    if (body.ref === WEBHOOK_REF) {
      let deploy = spawn(DEPLOY_SCRIPT, { cwd: DEPLOY_DIRECTORY, shell: true });
      deploy.stdout.on("data", function(data) {
        console.log(data.toString());
      });
      deploy.stderr.on("data", function(data) {
        console.error(data.toString());
      });
      deploy.on("error", err => {
        console.error(err);
        res.sendStatus(500);
      });
      deploy.on("close", function(code) {
        if (code === 0) {
          res.sendStatus(200);
        } else {
          res.sendStatus(500);
        }
      });
    }
  }

  return next();
});

app.listen(PORT);
console.log(`http://localhost:${PORT}`);
