// Deploy-time configuration. The CloudFormation SPA deployer overwrites this file
// in S3 with the live API endpoint: window.TRAILWHISPERER_CONFIG = { apiBase: "https://..." };
// The committed copy is intentionally empty so local dev falls back to ?api= / localhost:8000.
window.TRAILWHISPERER_CONFIG = {};
